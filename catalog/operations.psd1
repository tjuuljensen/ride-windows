# Authoritative operation/group metadata. SchemaVersion 1; edit here and regenerate docs/OPERATIONS.md. Targets, scope, states, sources, and rollback limits are declared per operation.
# Owner: RIDE-Windows maintainers. Keep values as declarative data.
# Versioning: SchemaVersion governs the data contract; no independent script CLI/version.

@{
  SchemaVersion = 1
  Operations = @(
    @{
      Id = 'powershell.windows-powershell51-terminal-colors'
      Name = 'Windows PowerShell 5.1 session colors'
      Kind = 'ProfileSetting'
      Category = 'Profile settings / PowerShell'
      Description = 'Manage a current-user ConsoleHost startup block. Recommended applies Campbell in normal Windows Terminal sessions and Campbell PowerShell blue when the actual shell token is elevated. AdminBlue changes only elevated sessions. Default removes only this RIDE block; restore recovers captured profile content. Does not edit Terminal settings, PATH, execution policy or tab titles. Existing sessions and other shells are unaffected.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ProfileSetting'
      ProfileRuntime = 'WindowsPowerShell51'
      ProfileSetting = 'TerminalColors'
      NormalColorScheme = 'Campbell'
      AdminColorScheme = 'Campbell PowerShell'
      States = @{ Recommended = 'Recommended'; AdminBlue = 'AdminBlue'; Default = $null }
      BaselineState = 'Default'
      UnsetState = 'Default'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Default'; EffectiveDefault = 'No RIDE startup override; configured Windows Terminal appearance' }
        'Windows Server 2025' = @{ DefaultValue = 'Default'; EffectiveDefault = 'No RIDE startup override; configured Windows Terminal appearance' }
      }
      Rollback = 'Exact'
      SettingPresentation = @{
        AppliesTo = 'Current user; Windows PowerShell 5.1 ConsoleHost startup in Windows Terminal'
        Behavior = 'Preference'
        GuiEffect = 'New normal sessions use Campbell; elevated sessions use blue. Inherited elevation is detected from the actual token. NoProfile and blocked startup scripts bypass this setting.'
        GuiPath = 'CurrentUserCurrentHost PowerShell startup profile; Terminal settings are preserved'
        Requirements = @('Installed Windows PowerShell 5.1 and Windows Terminal; profile execution permitted', 'Apply in the intended user context; another administrator account has its own profile', 'Server requires Desktop Experience; cloud hydration remains unverified')
        OtherSupportedChoices = @('AdminBlue preserves normal-session appearance', 'Default/unset remove the RIDE block; Baseline selects Default', 'Saved-run restore recovers the prior managed content and preserves unrelated edits')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles', 'https://learn.microsoft.com/en-us/windows/terminal/customize-settings/color-schemes', 'https://learn.microsoft.com/en-us/windows/terminal/customize-settings/profile-general#automatically-run-as-administrator')
      }
    }
    @{
      Id = 'powershell.powershell7-terminal-colors'
      Name = 'PowerShell 7 session colors'
      Kind = 'ProfileSetting'
      Category = 'Profile settings / PowerShell'
      Description = 'Manage a current-user ConsoleHost startup block. Recommended applies One Half Dark in normal Windows Terminal sessions and Campbell PowerShell blue when the actual shell token is elevated. AdminBlue changes only elevated sessions. Default removes only this RIDE block; restore recovers captured profile content. Does not install PowerShell, edit Terminal settings, PATH, execution policy or tab titles. Existing sessions and other shells are unaffected.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ProfileSetting'
      ProfileRuntime = 'PowerShell7'
      ProfileSetting = 'TerminalColors'
      NormalColorScheme = 'One Half Dark'
      AdminColorScheme = 'Campbell PowerShell'
      States = @{ Recommended = 'Recommended'; AdminBlue = 'AdminBlue'; Default = $null }
      BaselineState = 'Default'
      UnsetState = 'Default'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Default'; EffectiveDefault = 'No RIDE startup override; configured Windows Terminal appearance' }
        'Windows Server 2025' = @{ DefaultValue = 'Default'; EffectiveDefault = 'No RIDE startup override; configured Windows Terminal appearance' }
      }
      Rollback = 'Exact'
      SettingPresentation = @{
        AppliesTo = 'Current user; installed PowerShell 7 ConsoleHost startup in Windows Terminal'
        Behavior = 'Preference'
        GuiEffect = 'New normal sessions use One Half Dark; elevated sessions use blue. Inherited elevation is detected from the actual token. NoProfile and blocked startup scripts bypass this setting.'
        GuiPath = 'CurrentUserCurrentHost PowerShell startup profile; Terminal settings are preserved'
        Requirements = @('Installed PowerShell 7 and Windows Terminal; profile execution permitted', 'Apply in the intended user context; another administrator account has its own profile', 'Server requires Desktop Experience; cloud hydration remains unverified')
        OtherSupportedChoices = @('AdminBlue preserves normal-session appearance', 'Default/unset remove the RIDE block; Baseline selects Default', 'Saved-run restore recovers the prior managed content and preserves unrelated edits')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles', 'https://learn.microsoft.com/en-us/windows/terminal/customize-settings/color-schemes', 'https://learn.microsoft.com/en-us/windows/terminal/customize-settings/profile-general#automatically-run-as-administrator')
      }
    }
    @{
      Id = 'windows.smartscreen-shell-policy'
      Name = 'SmartScreen checks for downloaded apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Configure Windows Shell SmartScreen checks. Does not configure Chromium Edge or remove antivirus protection. Retired EdgeHTML PhishingFilter writes are excluded. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-smartscreen#enablesmartscreeninshell'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
      ValueName = 'EnableSmartScreen'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableSmartScreen', 'EnableSmartScreen')
    }
    @{
      Id = 'windows.search-web-policy'
      Name = 'Web search policy (edition dependent)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the documented web-search policy. Enforcement is edition and build dependent; it is not a guaranteed universal Start/Bing switch. CortanaConsent and obsolete BingSearchEnabled preferences are excluded. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#disablewebsearch'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
      ValueName = 'DisableWebSearch'
      ValueType = 'DWord'
      States = @{ 'Blocked' = 1; 'Allowed' = 0; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableWebSearch', 'EnableWebSearch')
    }
    @{
      Id = 'windows.firewall-standard-profile-policy'
      Name = 'Firewall for the legacy standard profile'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Configure only the legacy StandardProfile firewall policy. Does not disable every current firewall profile or change rules. Modern domain/private/public policy precedence requires target verification. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile'
      ValueName = 'EnableFirewall'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableFirewall', 'EnableFirewall')
    }
    @{
      Id = 'windows.security-notification-icon'
      Name = 'Windows Security notification-area icon'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Hide or show the Windows Security tray icon using policy. Protection continues independently. Legacy SecurityHealth startup-entry removal is excluded. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsdefendersecuritycenter#hidewindowssecuritynotificationareacontrol'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray'
      ValueName = 'HideSystray'
      ValueType = 'DWord'
      States = @{ 'Hidden' = 1; 'Shown' = 0; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideDefenderTrayIcon', 'ShowDefenderTrayIcon')
    }
    @{
      Id = 'windows.memory-integrity-request'
      Name = 'Memory integrity enablement request'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Write the HVCI enablement preference. Running protection still requires compatible hardware, VBS configuration, drivers and restart; this operation neither provisions those dependencies nor changes UEFI locks. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#enable-memory-integrity-using-registry'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
      ValueName = 'Enabled'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('EnableCIMemoryIntegrity', 'DisableCIMemoryIntegrity')
    }
    @{
      Id = 'windows.defender-cloud-membership'
      Name = 'Cloud-delivered protection (Microsoft Defender Antivirus)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Configure cloud-delivered protection independently of automatic sample submission. Advanced enables the legacy MAPS reporting choice; Basic and Advanced have the same effect on Windows 11. This is built-in Defender Antivirus protection, with no separate Microsoft 365 or Defender for Endpoint subscription. Local configuration procedures imply no Microsoft-account sign-in, paid membership registration or Endpoint onboarding requirement; local-account VM acceptance remains pending. Operational Defender Antivirus and Microsoft cloud connectivity are required. Tamper protection and managed policy may block or override changes; inspecting this registry value does not prove effective protection. WindowsDefault removes only this override; saved-run restore recovers its prior value and type.'
      SettingPresentation = @{
        AppliesTo = 'Device: Microsoft Defender Antivirus cloud-delivered protection'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection'
        GuiEffect = 'Machine policy; tamper protection or managed policy can block or override it. Current GUI locking and effective protection require VM acceptance.'
        Requirements = @('Windows 11 with operational Microsoft Defender Antivirus and Microsoft cloud connectivity', 'Built-in protection: no separate Microsoft 365 or Defender for Endpoint subscription or paid MAPS membership', 'No Microsoft-account sign-in or Endpoint onboarding step in local procedures (inference; local-account VM acceptance pending)')
        OtherSupportedChoices = @('Automatic sample submission is a separate control; Advanced is not a premium subscription or cloud blocking level')
        ReferenceUris = @('https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure', 'https://support.microsoft.com/en-us/security/keep-your-computer-secure-at-home')
      }
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowcloudprotection'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
      ValueName = 'SpynetReporting'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Advanced' = 2; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableDefenderCloud', 'EnableDefenderCloud')
    }
    @{
      Id = 'windows.defender-sample-submission'
      Name = 'Defender automatic sample submission'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Choose prompt, automatic safe samples, never send, or send all samples. This is distinct from cloud-protection membership. Restoring the preference cannot retract already submitted files; tamper protection can override or reject changes. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#submitsamplesconsent'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
      ValueName = 'SubmitSamplesConsent'
      ValueType = 'DWord'
      States = @{ 'Prompt' = 0; 'SafeSamples' = 1; 'Never' = 2; 'AllSamples' = 3; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableDefenderCloud', 'EnableDefenderCloud')
    }
    @{
      Id = 'windows.unidentified-network-category'
      Name = 'Unidentified network location policy (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Retain the legacy unidentified-network policy signature and Public/Private values. Microsoft reference explains the network area, not this fixed signature mapping. Current Network List Manager behavior remains unverified; does not recategorize every active adapter. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-list-manager-policies#unidentified-networks'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24'
      ValueName = 'Category'
      ValueType = 'DWord'
      States = @{ 'Private' = 1; 'Public' = 0; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetUnknownNetworksPrivate', 'SetUnknownNetworksPublic')
    }
    @{
      Id = 'windows.network-device-auto-setup'
      Name = 'Automatic setup of devices on private networks (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Set the legacy private-network automatic-device-setup preference. Does not uninstall devices, change discovery protocols or choose a firewall profile. The Microsoft behavior reference does not specify this registry value; verify current-build effects. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private'
      ValueName = 'AutoSetup'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableNetDevicesAutoInst', 'EnableNetDevicesAutoInst')
    }
    @{
      Id = 'windows.connection-sharing-ui'
      Name = 'Internet Connection Sharing user interface'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Control the policy governing the shared-access UI. Hidden prevents the relevant sharing configuration UI; it does not stop SharedAccess, remove an existing shared connection or universally disable ICS. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-networkconnections'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
      ValueName = 'NC_ShowSharedAccessUI'
      ValueType = 'DWord'
      States = @{ 'Hidden' = 0; 'Available' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableConnectionSharing', 'EnableConnectionSharing')
    }
    @{
      Id = 'windows.hardware-clock-time-basis'
      Name = 'Hardware clock time basis (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Services'
      Description = 'Select the legacy local/UTC hardware-clock preference. Does not set the current time, time zone or Windows Time service. Microsoft reference explains system time, not this registry mapping; dual-boot and restart behavior remain unverified. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/sysinfo/system-time'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
      ValueName = 'RealTimeIsUniversal'
      ValueType = 'DWord'
      States = @{ 'Local' = 0; 'UTC' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetBIOSTimeUTC', 'SetBIOSTimeLocal')
    }
    @{
      Id = 'windows.sleep-menu-option'
      Name = 'Sleep option in the power menu'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Services'
      Description = 'Show or hide the legacy Sleep menu preference. Available sleep states and policy still govern whether it appears. The link documents sleep-button behavior, not ShowSleepOption. Keyboard sleep-button actions are separate operations. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-sleep-button-action'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings'
      ValueName = 'ShowSleepOption'
      ValueType = 'DWord'
      States = @{ 'Hidden' = 0; 'Shown' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableSleepButton', 'EnableSleepButton')
    }
    @{
      Id = 'windows.window-drag-content'
      Name = 'Show window contents while dragging'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Choose an outline or full window contents during dragging. The API reference documents drag-full-windows behavior; this retained registry preference needs sign-in/UI acceptance. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\Desktop'
      ValueName = 'DragFullWindows'
      ValueType = 'String'
      States = @{ 'Outline' = '0'; 'Contents' = '1'; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetVisualFXPerformance', 'SetVisualFXAppearance')
    }
    @{
      Id = 'windows.menu-open-delay'
      Name = 'Menu opening delay'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Set the menu-open delay to zero or the legacy 400 milliseconds. Does not change every application''s menus; the API reference describes the behavior rather than guaranteeing this registry mapping. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\Desktop'
      ValueName = 'MenuShowDelay'
      ValueType = 'String'
      States = @{ 'Immediate' = '0'; 'Delay400ms' = '400'; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetVisualFXPerformance', 'SetVisualFXAppearance')
    }
    @{
      Id = 'windows.window-minimize-animation'
      Name = 'Minimize and restore window animation'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Choose the legacy minimize/restore animation preference. Does not overwrite the packed UserPreferencesMask or the complete Visual Effects selection. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\Desktop\WindowMetrics'
      ValueName = 'MinAnimate'
      ValueType = 'String'
      States = @{ 'Disabled' = '0'; 'Enabled' = '1'; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetVisualFXPerformance', 'SetVisualFXAppearance')
    }
    @{
      Id = 'windows.keyboard-repeat-delay'
      Name = 'Keyboard repeat delay'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Choose repeat-delay index 0 or 1, not key-repeat speed. Corrects the legacy DWORD write to the Windows string preference; the API behavior reference does not specify this registry representation. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\Keyboard'
      ValueName = 'KeyboardDelay'
      ValueType = 'String'
      States = @{ 'Shortest' = '0'; 'LegacyAppearance' = '1'; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetVisualFXPerformance', 'SetVisualFXAppearance')
    }
    @{
      Id = 'windows.selection-rectangle-transparency'
      Name = 'Translucent Explorer selection rectangle'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Set the legacy Explorer selection-rectangle transparency preference. Does not change checkbox selection or thumbnail behavior. The reference is visual-effects background; verify current Explorer rendering. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'ListviewAlphaSelect'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetVisualFXPerformance', 'SetVisualFXAppearance')
    }
    @{
      Id = 'windows.desktop-label-shadows'
      Name = 'Shadows under desktop icon labels'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Set the legacy shadow preference for desktop icon text. Does not hide icons or change the desktop background. The reference documents visual-effects APIs, not this exact value. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'ListviewShadow'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetVisualFXPerformance', 'SetVisualFXAppearance')
    }
    @{
      Id = 'windows.desktop-peek'
      Name = 'Desktop Peek preference'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Set the legacy desktop-composition Peek preference. Does not implement every taskbar preview or enable DWM. The Microsoft reference explains composition, not this retained value; current Windows 11 effect needs UI verification. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/dwm/dwm-overview'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\DWM'
      ValueName = 'EnableAeroPeek'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetVisualFXPerformance', 'SetVisualFXAppearance')
    }
    @{
      Id = 'windows.explorer-network-icon'
      Name = 'Network entry in Explorer'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Hide/show enumeration of the Network shell entry. Does not disable networking or remove network devices. Microsoft documents namespace junctions, not this NonEnum preference; current Explorer acceptance remains required. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum'
      ValueName = '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}'
      ValueType = 'DWord'
      States = @{ 'Hidden' = 1; 'Visible' = 0; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideNetworkFromExplorer', 'ShowNetworkInExplorer')
    }
    @{
      Id = 'windows.bitlocker-enhanced-pin'
      Name = 'BitLocker enhanced startup PIN characters'
      Kind = 'RegistryValue'
      Category = 'Windows settings / BitLocker'
      Description = 'Allow enhanced PIN characters by policy. Does not create a PIN, enroll encryption or escrow recovery data. Preboot keyboard layout and hardware must support the chosen characters; the legacy interactive keyboard warning is replaced by this documented prerequisite. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
      ValueName = 'UseEnhancedPin'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('EnableEnhancedPIN', 'DisableEnhancedPIN')
    }
    @{
      Id = 'windows.bitlocker-additional-startup-auth'
      Name = 'BitLocker additional startup authentication policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / BitLocker'
      Description = 'Enable the additional-authentication policy gate. Related TPM/PIN/key policy values remain independent; this gate does not require or enroll TPM+PIN by itself, or alter existing protectors. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
      ValueName = 'UseAdvancedStartup'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('EnableAdditionalAuthAtStart')
    }
    @{
      Id = 'windows.onedrive-file-sync-policy'
      Name = 'OneDrive file synchronization policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Prevent or permit OneDrive file synchronization under the legacy policy. Does not uninstall OneDrive or delete synchronized files. Existing business-client/tenant policies and running-client refresh remain relevant. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#disableonedrivefilesync'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
      ValueName = 'DisableFileSyncNGSC'
      ValueType = 'DWord'
      States = @{ 'Blocked' = 1; 'Allowed' = 0; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableOneDrive', 'EnableOneDrive')
    }
    @{
      Id = 'windows.first-logon-animation'
      Name = 'First sign-in animation'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Control the policy for the animation shown during first sign-in. Existing signed-in sessions are unaffected; new-user testing is required. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-logon'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      ValueName = 'EnableFirstLogonAnimation'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableFirstLogonAnimation', 'EnableFirstLogonAnimation')
    }
    @{
      Id = 'windows.media-player-library-sharing'
      Name = 'Windows Media Player Legacy library sharing'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Prevent network media-library sharing by Windows Media Player Legacy. UserChoice permits user control rather than starting sharing. Does not affect all media applications. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventlibrarysharing'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
      ValueName = 'PreventLibrarySharing'
      ValueType = 'DWord'
      States = @{ 'Blocked' = 1; 'UserChoice' = 0; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableMediaSharing', 'EnableMediaSharing')
    }
    @{
      Id = 'windows.media-player-disc-metadata'
      Name = 'Windows Media Player Legacy CD/DVD metadata'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Prevent internet retrieval of CD/DVD media information in Windows Media Player Legacy. UserChoice permits its privacy option. Does not block music-file metadata, codecs or all online media traffic. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventcddvdmetadataretrieval'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
      ValueName = 'PreventCDDVDMetadataRetrieval'
      ValueType = 'DWord'
      States = @{ 'Blocked' = 1; 'UserChoice' = 0; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableMediaOnlineAccess', 'EnableMediaOnlineAccess')
    }
    @{
      Id = 'windows.media-player-music-metadata'
      Name = 'Windows Media Player Legacy music-file metadata'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Prevent internet retrieval of music-file media information in Windows Media Player Legacy. Separate from CD/DVD metadata. Retired radio presets and WMDRM online controls from the legacy bundle remain excluded. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventmusicfilemetadataretrieval'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
      ValueName = 'PreventMusicFileMetadataRetrieval'
      ValueType = 'DWord'
      States = @{ 'Blocked' = 1; 'UserChoice' = 0; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableMediaOnlineAccess', 'EnableMediaOnlineAccess')
    }
    @{
      Id = 'windows.developer-mode-preference'
      Name = 'Developer Mode local preference'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Set the local Developer Mode preference. Does not install developer packages, enable Device Portal, or configure SSH. Managed policy can override it; the behavior reference does not guarantee this local value on every build. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/advanced-settings/developer-mode'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
      ValueName = 'AllowDevelopmentWithoutDevLicense'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('EnableDeveloperMode', 'DisableDeveloperMode')
    }
    @{
      Id = 'windows.trusted-app-sideload-preference'
      Name = 'Trusted app sideloading local preference'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Set the legacy local preference permitting trusted app sideloading. Distinct from full Developer Mode and Appx deployment policy. Does not install an app, certificate or developer license; current-build enforcement needs verification. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/advanced-settings/developer-mode'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
      ValueName = 'AllowAllTrustedApps'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('EnableDeveloperMode', 'DisableDeveloperMode')
    }
    @{
      Id = 'windows.game-mode-preference'
      Name = 'Game Mode user preference (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Retain only the Game Mode preference from the Xbox bundle. Does not remove Xbox apps or control recording. Microsoft support is feature background, not this registry mapping; verify on current Windows 11 before recommending it. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://support.microsoft.com/en-us/accessibility/windows/understand-and-explore-windows-settings'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\GameBar'
      ValueName = 'AutoGameModeEnabled'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableXboxFeatures', 'EnableXboxFeatures')
    }
    @{
      Id = 'windows.game-recording-user-preference'
      Name = 'Game recording user preference (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Retain the user GameDVR preference independently of machine policy. Does not remove Xbox/Game Bar apps. The Microsoft link documents machine recording policy, not this value; verify current recording behavior. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationmanagement#allowgamedvr'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\System\GameConfigStore'
      ValueName = 'GameDVR_Enabled'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableXboxFeatures', 'EnableXboxFeatures')
    }
    @{
      Id = 'windows.game-recording-policy'
      Name = 'Game recording policy (experimental on Windows 11)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Applications'
      Description = 'Set the legacy Game Recording and Broadcasting policy. Microsoft currently limits enforcement to Windows 10 desktop; effectiveness on the declared Windows 11 target is unverified. This is a retained experimental mapping, not a promised Xbox-features switch. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationmanagement#allowgamedvr'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
      ValueName = 'AllowGameDVR'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Allowed' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableXboxFeatures', 'EnableXboxFeatures')
    }
    @{
      Id = 'windows.taskbar-animation-preference'
      Name = 'Taskbar animation preference (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Retain the legacy taskbar-animation preference from the visual-effects bundle. Windows 11 taskbar rendering may ignore it. No packed visual-effects data or shell process is changed; current visual acceptance remains pending. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'TaskbarAnimations'
      ValueType = 'DWord'
      States = @{ 'Disabled' = 0; 'Enabled' = 1; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetVisualFXPerformance', 'SetVisualFXAppearance')
    }
    @{
      Id = 'windows.shortcut-name-suffix'
      Name = 'Shortcut name suffix preference'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Write four zero bytes to suppress the legacy suffix preference for newly created shortcuts. Enabled removes the override as the legacy reverse selector did; it does not rename existing shortcuts. Microsoft documents shell links, not this binary value. Saved-run restore recovers the original bytes and registry type; current naming behavior remains unverified.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/links'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
      ValueName = 'link'
      ValueType = 'Binary'
      States = @{ 'Disabled' = @(0, 0, 0, 0); 'Enabled' = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValueExists' = $null; 'DefaultValue' = $null; 'EffectiveDefault' = 'Literal defaults depend on image, edition, policy and user configuration; removing the override delegates to Windows and other applicable controls' } }
      Rollback = 'Exact'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableShortcutInName', 'EnableShortcutInName')
    }
    @{
      Id = 'windows.desktop-folder-this-pc'
      Name = 'Desktop folder in This PC'
      Kind = 'RegistryKeySet'
      Category = 'Windows settings / Explorer'
      Description = 'Hide or register only the Desktop shell namespace keys in This PC. Folder contents are preserved. Visible creates missing empty registration roots; baseline Visible is a RIDE choice, not the image default. Exact restore reconstructs captured subtrees, typed values and security. Current Explorer presentation requires acceptance; no shell restart is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryKeySet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}')
      States = @{ 'Hidden' = 'Absent'; 'Visible' = 'Present' }
      BaselineState = 'Visible'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideDesktopFromThisPC', 'ShowDesktopInThisPC')
    }
    @{
      Id = 'windows.documents-folder-this-pc'
      Name = 'Documents folder in This PC'
      Kind = 'RegistryKeySet'
      Category = 'Windows settings / Explorer'
      Description = 'Hide or register only the Documents shell namespace keys in This PC. Folder contents are preserved. Visible creates missing empty registration roots; baseline Visible is a RIDE choice, not the image default. Exact restore reconstructs captured subtrees, typed values and security. Current Explorer presentation requires acceptance; no shell restart is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryKeySet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}')
      States = @{ 'Hidden' = 'Absent'; 'Visible' = 'Present' }
      BaselineState = 'Visible'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideDocumentsFromThisPC', 'ShowDocumentsInThisPC')
    }
    @{
      Id = 'windows.downloads-folder-this-pc'
      Name = 'Downloads folder in This PC'
      Kind = 'RegistryKeySet'
      Category = 'Windows settings / Explorer'
      Description = 'Hide or register only the Downloads shell namespace keys in This PC. Folder contents are preserved. Visible creates missing empty registration roots; baseline Visible is a RIDE choice, not the image default. Exact restore reconstructs captured subtrees, typed values and security. Current Explorer presentation requires acceptance; no shell restart is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryKeySet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}')
      States = @{ 'Hidden' = 'Absent'; 'Visible' = 'Present' }
      BaselineState = 'Visible'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideDownloadsFromThisPC', 'ShowDownloadsInThisPC')
    }
    @{
      Id = 'windows.pictures-folder-this-pc'
      Name = 'Pictures folder in This PC'
      Kind = 'RegistryKeySet'
      Category = 'Windows settings / Explorer'
      Description = 'Hide or register only the Pictures shell namespace keys in This PC. Folder contents are preserved. Visible creates missing empty registration roots; baseline Visible is a RIDE choice, not the image default. Exact restore reconstructs captured subtrees, typed values and security. Current Explorer presentation requires acceptance; no shell restart is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryKeySet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}')
      States = @{ 'Hidden' = 'Absent'; 'Visible' = 'Present' }
      BaselineState = 'Visible'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HidePicturesFromThisPC', 'ShowPicturesInThisPC')
    }
    @{
      Id = 'windows.telemetry-service'
      Name = 'Connected User Experiences and Telemetry service'
      Kind = 'WindowsService'
      Category = 'Windows settings / Services'
      Description = 'Disabled stops the service and sets Disabled startup. AutomaticRunning sets Automatic and starts it. Disabling this service is not a guarantee of zero telemetry traffic. Baseline AutomaticRunning is an explicit RIDE choice. Capture and restore startup mode and running state; a missing service is an error rather than an invented default.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'WindowsService'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PreserveDelayedAutoStart = $true
      ServiceName = 'DiagTrack'
      States = @{ 'Disabled' = @{ 'StartupType' = 'Disabled'; 'Status' = 'Stopped' }; 'AutomaticRunning' = @{ 'StartupType' = 'Automatic'; 'Status' = 'Running' } }
      BaselineState = 'AutomaticRunning'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableDiagTrack', 'EnableDiagTrack')
    }
    @{
      Id = 'windows.wap-push-service'
      Name = 'Device Management WAP Push service'
      Kind = 'WindowsService'
      Category = 'Windows settings / Services'
      Description = 'Disabled stops the service and sets Disabled startup. AutomaticRunning sets Automatic and starts it. The legacy reverse also set DelayedAutoStart; that scheduling override is excluded and remains partial. Device-management workloads may depend on this service. Baseline AutomaticRunning is an explicit RIDE choice. Capture and restore startup mode and running state; a missing service is an error rather than an invented default.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'WindowsService'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PreserveDelayedAutoStart = $true
      ServiceName = 'dmwappushservice'
      States = @{ 'Disabled' = @{ 'StartupType' = 'Disabled'; 'Status' = 'Stopped' }; 'AutomaticRunning' = @{ 'StartupType' = 'Automatic'; 'Status' = 'Running' } }
      BaselineState = 'AutomaticRunning'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableWAPPush', 'EnableWAPPush')
    }
    @{
      Id = 'windows.sysmain-service'
      Name = 'SysMain prefetch service'
      Kind = 'WindowsService'
      Category = 'Windows settings / Services'
      Description = 'Disabled stops the service and sets Disabled startup. AutomaticRunning sets Automatic and starts it. The historical Superfetch selector controls SysMain; this does not clear prefetch data. Baseline AutomaticRunning is an explicit RIDE choice. Capture and restore startup mode and running state; a missing service is an error rather than an invented default.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'WindowsService'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PreserveDelayedAutoStart = $true
      ServiceName = 'SysMain'
      States = @{ 'Disabled' = @{ 'StartupType' = 'Disabled'; 'Status' = 'Stopped' }; 'AutomaticRunning' = @{ 'StartupType' = 'Automatic'; 'Status' = 'Running' } }
      BaselineState = 'AutomaticRunning'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableSuperfetch', 'EnableSuperfetch')
    }
    @{
      Id = 'windows.search-indexing-service'
      Name = 'Windows Search indexing service'
      Kind = 'WindowsService'
      Category = 'Windows settings / Services'
      Description = 'Disabled stops the service and sets Disabled startup. AutomaticRunning sets Automatic and starts it. The legacy reverse also set DelayedAutoStart; that override is excluded. Disabling can impair indexed search; no index files are deleted. Baseline AutomaticRunning is an explicit RIDE choice. Capture and restore startup mode and running state; a missing service is an error rather than an invented default.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'WindowsService'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PreserveDelayedAutoStart = $true
      ServiceName = 'WSearch'
      States = @{ 'Disabled' = @{ 'StartupType' = 'Disabled'; 'Status' = 'Stopped' }; 'AutomaticRunning' = @{ 'StartupType' = 'Automatic'; 'Status' = 'Running' } }
      BaselineState = 'AutomaticRunning'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableIndexing', 'EnableIndexing')
    }
    @{
      Id = 'windows.sleep-button-action-ac'
      Name = 'Sleep button action on AC power'
      Kind = 'PowerSetting'
      Category = 'Windows settings / Power'
      Description = 'Change only the AC index in the active power scheme. DoNothing ignores the hardware sleep button; Sleep requests supported sleep. The menu preference is separate. Capture the scheme GUID and exact index. Unsupported hardware or schemes report Unavailable. Does not change the active scheme, hibernation or unrelated indexes.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-sleep-button-action'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'PowerSetting'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'Platform-defined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PowerSubgroupGuid = '4f971e89-eebd-4455-a8de-9e59040e7347'
      PowerSettingGuid = '96996bc0-ad50-47ec-923b-6f41874dd9eb'
      PowerIndex = 'AC'
      States = @{ 'DoNothing' = 0; 'Sleep' = 1 }
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableSleepButton', 'EnableSleepButton')
    }
    @{
      Id = 'windows.sleep-button-action-dc'
      Name = 'Sleep button action on battery'
      Kind = 'PowerSetting'
      Category = 'Windows settings / Power'
      Description = 'Change only the DC index in the active power scheme. DoNothing ignores the hardware sleep button; Sleep requests supported sleep. The menu preference is separate. Capture the scheme GUID and exact index. Unsupported hardware or schemes report Unavailable. Does not change the active scheme, hibernation or unrelated indexes.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-sleep-button-action'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'PowerSetting'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'Platform-defined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PowerSubgroupGuid = '4f971e89-eebd-4455-a8de-9e59040e7347'
      PowerSettingGuid = '96996bc0-ad50-47ec-923b-6f41874dd9eb'
      PowerIndex = 'DC'
      States = @{ 'DoNothing' = 0; 'Sleep' = 1 }
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableSleepButton', 'EnableSleepButton')
    }
    @{
      Id = 'windows.display-idle-timeout-ac'
      Name = 'Display idle timeout on AC power'
      Kind = 'PowerSetting'
      Category = 'Windows settings / Power'
      Description = 'Change only the AC index in the active power scheme. Timeout values are seconds; Never writes 0. The named timed state reproduces the legacy duration, not a universal Windows default. Capture the scheme GUID and exact index. Unsupported hardware or schemes report Unavailable. Does not change the active scheme, hibernation or unrelated indexes.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/display-settings-display-idle-timeout'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'PowerSetting'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'Platform-defined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PowerSubgroupGuid = '7516b95f-f776-4464-8c53-06167f40cc99'
      PowerSettingGuid = '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
      PowerIndex = 'AC'
      States = @{ 'Never' = 0; 'TenMinutes' = 600 }
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableSleepTimeout', 'EnableSleepTimeout')
    }
    @{
      Id = 'windows.display-idle-timeout-dc'
      Name = 'Display idle timeout on battery'
      Kind = 'PowerSetting'
      Category = 'Windows settings / Power'
      Description = 'Change only the DC index in the active power scheme. Timeout values are seconds; Never writes 0. The named timed state reproduces the legacy duration, not a universal Windows default. Capture the scheme GUID and exact index. Unsupported hardware or schemes report Unavailable. Does not change the active scheme, hibernation or unrelated indexes.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/display-settings-display-idle-timeout'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'PowerSetting'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'Platform-defined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PowerSubgroupGuid = '7516b95f-f776-4464-8c53-06167f40cc99'
      PowerSettingGuid = '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
      PowerIndex = 'DC'
      States = @{ 'Never' = 0; 'FiveMinutes' = 300 }
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableSleepTimeout', 'EnableSleepTimeout')
    }
    @{
      Id = 'windows.sleep-idle-timeout-ac'
      Name = 'Sleep idle timeout on AC power'
      Kind = 'PowerSetting'
      Category = 'Windows settings / Power'
      Description = 'Change only the AC index in the active power scheme. Timeout values are seconds; Never writes 0. The named timed state reproduces the legacy duration, not a universal Windows default. Capture the scheme GUID and exact index. Unsupported hardware or schemes report Unavailable. Does not change the active scheme, hibernation or unrelated indexes.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-idle-timeout'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'PowerSetting'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'Platform-defined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PowerSubgroupGuid = '238c9fa8-0aad-41ed-83f4-97be242c8f20'
      PowerSettingGuid = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da'
      PowerIndex = 'AC'
      States = @{ 'Never' = 0; 'ThirtyMinutes' = 1800 }
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableSleepTimeout', 'EnableSleepTimeout')
    }
    @{
      Id = 'windows.sleep-idle-timeout-dc'
      Name = 'Sleep idle timeout on battery'
      Kind = 'PowerSetting'
      Category = 'Windows settings / Power'
      Description = 'Change only the DC index in the active power scheme. Timeout values are seconds; Never writes 0. The named timed state reproduces the legacy duration, not a universal Windows default. Capture the scheme GUID and exact index. Unsupported hardware or schemes report Unavailable. Does not change the active scheme, hibernation or unrelated indexes.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-idle-timeout'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'PowerSetting'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'Platform-defined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PowerSubgroupGuid = '238c9fa8-0aad-41ed-83f4-97be242c8f20'
      PowerSettingGuid = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da'
      PowerIndex = 'DC'
      States = @{ 'Never' = 0; 'FifteenMinutes' = 900 }
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableSleepTimeout', 'EnableSleepTimeout')
    }
    @{
      Id = 'windows.boot-failure-recovery-policy'
      Name = 'Automatic recovery after boot failures'
      Kind = 'BootConfiguration'
      Category = 'Windows settings / Security'
      Description = 'Choose the boot-status policy for the current boot entry. IgnoreAllFailures suppresses automatic recovery triggered by boot failures. WindowsDefault removes the override. Does not run reagentc, disable Windows RE or factory-reset capabilities. Exact BCD value/existence restore; effects require restart and remain unverified without reboot acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#boot-settings'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'BootConfiguration'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      BcdElement = 'bootstatuspolicy'
      States = @{ 'IgnoreAllFailures' = 'IgnoreAllFailures'; 'WindowsDefault' = $null }
      BaselineState = 'WindowsDefault'
      RestartRequired = $true
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableBootRecovery', 'EnableBootRecovery')
    }
    @{
      Id = 'windows.desktop-folder-shell-policy'
      Name = 'Desktop shell folder visibility (experimental)'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Explorer'
      Description = 'Set both native and 32-bit shell-folder visibility preferences for Desktop. Keeps the architecture mirrors inside one feature, distinct from This PC namespace-key registration. Does not move/delete folders or control pinned Home shortcuts. Microsoft documents known-folder behavior, not this ThisPCPolicy mapping; current Explorer presentation is unverified. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/known-folders'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Native'; 'RegistryPath' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' }, @{ 'Key' = 'Wow32'; 'RegistryPath' = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' })
      States = @{ 'Hidden' = @{ 'Native' = 'Hide'; 'Wow32' = 'Hide' }; 'Visible' = @{ 'Native' = 'Show'; 'Wow32' = 'Show' }; 'WindowsDefault' = @{ 'Native' = $null; 'Wow32' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideDesktopFromExplorer', 'ShowDesktopInExplorer')
    }
    @{
      Id = 'windows.documents-folder-shell-policy'
      Name = 'Documents shell folder visibility (experimental)'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Explorer'
      Description = 'Set both native and 32-bit shell-folder visibility preferences for Documents. Keeps the architecture mirrors inside one feature, distinct from This PC namespace-key registration. Does not move/delete folders or control pinned Home shortcuts. Microsoft documents known-folder behavior, not this ThisPCPolicy mapping; current Explorer presentation is unverified. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/known-folders'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Native'; 'RegistryPath' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' }, @{ 'Key' = 'Wow32'; 'RegistryPath' = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' })
      States = @{ 'Hidden' = @{ 'Native' = 'Hide'; 'Wow32' = 'Hide' }; 'Visible' = @{ 'Native' = 'Show'; 'Wow32' = 'Show' }; 'WindowsDefault' = @{ 'Native' = $null; 'Wow32' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideDocumentsFromExplorer', 'ShowDocumentsInExplorer')
    }
    @{
      Id = 'windows.downloads-folder-shell-policy'
      Name = 'Downloads shell folder visibility (experimental)'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Explorer'
      Description = 'Set both native and 32-bit shell-folder visibility preferences for Downloads. Keeps the architecture mirrors inside one feature, distinct from This PC namespace-key registration. Does not move/delete folders or control pinned Home shortcuts. Microsoft documents known-folder behavior, not this ThisPCPolicy mapping; current Explorer presentation is unverified. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/known-folders'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Native'; 'RegistryPath' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' }, @{ 'Key' = 'Wow32'; 'RegistryPath' = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' })
      States = @{ 'Hidden' = @{ 'Native' = 'Hide'; 'Wow32' = 'Hide' }; 'Visible' = @{ 'Native' = 'Show'; 'Wow32' = 'Show' }; 'WindowsDefault' = @{ 'Native' = $null; 'Wow32' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideDownloadsFromExplorer', 'ShowDownloadsInExplorer')
    }
    @{
      Id = 'windows.music-folder-shell-policy'
      Name = 'Music shell folder visibility (experimental)'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Explorer'
      Description = 'Set both native and 32-bit shell-folder visibility preferences for Music. Keeps the architecture mirrors inside one feature, distinct from This PC namespace-key registration. Does not move/delete folders or control pinned Home shortcuts. Microsoft documents known-folder behavior, not this ThisPCPolicy mapping; current Explorer presentation is unverified. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/known-folders'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Native'; 'RegistryPath' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' }, @{ 'Key' = 'Wow32'; 'RegistryPath' = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' })
      States = @{ 'Hidden' = @{ 'Native' = 'Hide'; 'Wow32' = 'Hide' }; 'Visible' = @{ 'Native' = 'Show'; 'Wow32' = 'Show' }; 'WindowsDefault' = @{ 'Native' = $null; 'Wow32' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideMusicFromExplorer', 'ShowMusicInExplorer')
    }
    @{
      Id = 'windows.pictures-folder-shell-policy'
      Name = 'Pictures shell folder visibility (experimental)'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Explorer'
      Description = 'Set both native and 32-bit shell-folder visibility preferences for Pictures. Keeps the architecture mirrors inside one feature, distinct from This PC namespace-key registration. Does not move/delete folders or control pinned Home shortcuts. Microsoft documents known-folder behavior, not this ThisPCPolicy mapping; current Explorer presentation is unverified. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/known-folders'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Native'; 'RegistryPath' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' }, @{ 'Key' = 'Wow32'; 'RegistryPath' = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' })
      States = @{ 'Hidden' = @{ 'Native' = 'Hide'; 'Wow32' = 'Hide' }; 'Visible' = @{ 'Native' = 'Show'; 'Wow32' = 'Show' }; 'WindowsDefault' = @{ 'Native' = $null; 'Wow32' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HidePicturesFromExplorer', 'ShowPicturesInExplorer')
    }
    @{
      Id = 'windows.videos-folder-shell-policy'
      Name = 'Videos shell folder visibility (experimental)'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Explorer'
      Description = 'Set both native and 32-bit shell-folder visibility preferences for Videos. Keeps the architecture mirrors inside one feature, distinct from This PC namespace-key registration. Does not move/delete folders or control pinned Home shortcuts. Microsoft documents known-folder behavior, not this ThisPCPolicy mapping; current Explorer presentation is unverified. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/known-folders'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Native'; 'RegistryPath' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' }, @{ 'Key' = 'Wow32'; 'RegistryPath' = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' })
      States = @{ 'Hidden' = @{ 'Native' = 'Hide'; 'Wow32' = 'Hide' }; 'Visible' = @{ 'Native' = 'Show'; 'Wow32' = 'Show' }; 'WindowsDefault' = @{ 'Native' = $null; 'Wow32' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('HideVideosFromExplorer', 'ShowVideosInExplorer')
    }
    @{
      Id = 'windows.3d-objects-folder-shell-policy'
      Name = '3D Objects shell folder visibility (experimental)'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Explorer'
      Description = 'Set both native and 32-bit shell-folder visibility preferences for 3D Objects. Keeps the architecture mirrors inside one feature, distinct from This PC namespace-key registration. Does not move/delete folders or control pinned Home shortcuts. Microsoft documents known-folder behavior, not this ThisPCPolicy mapping; current Explorer presentation is unverified. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/known-folders'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Native'; 'RegistryPath' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' }, @{ 'Key' = 'Wow32'; 'RegistryPath' = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag'; 'ValueName' = 'ThisPCPolicy'; 'ValueType' = 'String' })
      States = @{ 'Hidden' = @{ 'Native' = 'Hide'; 'Wow32' = 'Hide' }; 'Visible' = @{ 'Native' = 'Show'; 'Wow32' = 'Show' }; 'WindowsDefault' = @{ 'Native' = $null; 'Wow32' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('Hide3DObjectsFromExplorer', 'Show3DObjectsInExplorer')
    }
    @{
      Id = 'windows.control-panel-view'
      Name = 'Control Panel opening view'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / UI'
      Description = 'Choose the Control Panel view as one coherent preference. Categories explicitly writes 0 to both values; legacy categories removed both, reproduced by WindowsDefault. The Microsoft page describes Control Panel, not these two preferences; UI acceptance remains pending. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/control-panel-applications'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Page'; 'RegistryPath' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel'; 'ValueName' = 'StartupPage'; 'ValueType' = 'DWord' }, @{ 'Key' = 'Icons'; 'RegistryPath' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel'; 'ValueName' = 'AllItemsIconView'; 'ValueType' = 'DWord' })
      States = @{ 'SmallIcons' = @{ 'Page' = 1; 'Icons' = 1 }; 'LargeIcons' = @{ 'Page' = 1; 'Icons' = 0 }; 'Categories' = @{ 'Page' = 0; 'Icons' = 0 }; 'WindowsDefault' = @{ 'Page' = $null; 'Icons' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetControlPanelSmallIcons', 'SetControlPanelLargeIcons', 'SetControlPanelCategories')
    }
    @{
      Id = 'windows.mouse-pointer-precision'
      Name = 'Enhanced mouse pointer precision'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / UI'
      Description = 'Change the three legacy mouse acceleration preferences together. Does not change pointer speed or configure touchpad drivers. The API reference describes mouse thresholds/acceleration; direct registry application requires sign-in/UI acceptance. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Speed'; 'RegistryPath' = 'HKCU:\Control Panel\Mouse'; 'ValueName' = 'MouseSpeed'; 'ValueType' = 'String' }, @{ 'Key' = 'Threshold1'; 'RegistryPath' = 'HKCU:\Control Panel\Mouse'; 'ValueName' = 'MouseThreshold1'; 'ValueType' = 'String' }, @{ 'Key' = 'Threshold2'; 'RegistryPath' = 'HKCU:\Control Panel\Mouse'; 'ValueName' = 'MouseThreshold2'; 'ValueType' = 'String' })
      States = @{ 'Disabled' = @{ 'Speed' = '0'; 'Threshold1' = '0'; 'Threshold2' = '0' }; 'Enabled' = @{ 'Speed' = '1'; 'Threshold1' = '6'; 'Threshold2' = '10' }; 'WindowsDefault' = @{ 'Speed' = $null; 'Threshold1' = $null; 'Threshold2' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableEnhPointerPrecision', 'EnableEnhPointerPrecision')
    }
    @{
      Id = 'windows.fullscreen-optimizations'
      Name = 'Fullscreen optimization preferences (experimental)'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Applications'
      Description = 'Keep the four GameConfigStore preferences from the legacy fullscreen-optimizations selector together. The reference explains related windowed-game optimizations, not these values or an equivalent switch. Exact effects can depend on game and Windows build; exclude from recommended profiles until tested with a representative game. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/hardware/display-graphics/optimizations-for-windowed-games-in-windows-11'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'HonorDXGI'; 'RegistryPath' = 'HKCU:\System\GameConfigStore'; 'ValueName' = 'GameDVR_DXGIHonorFSEWindowsCompatible'; 'ValueType' = 'DWord' }, @{ 'Key' = 'Behavior'; 'RegistryPath' = 'HKCU:\System\GameConfigStore'; 'ValueName' = 'GameDVR_FSEBehavior'; 'ValueType' = 'DWord' }, @{ 'Key' = 'Mode'; 'RegistryPath' = 'HKCU:\System\GameConfigStore'; 'ValueName' = 'GameDVR_FSEBehaviorMode'; 'ValueType' = 'DWord' }, @{ 'Key' = 'HonorUser'; 'RegistryPath' = 'HKCU:\System\GameConfigStore'; 'ValueName' = 'GameDVR_HonorUserFSEBehaviorMode'; 'ValueType' = 'DWord' })
      States = @{ 'Disabled' = @{ 'HonorDXGI' = 1; 'Behavior' = 2; 'Mode' = 2; 'HonorUser' = 1 }; 'Enabled' = @{ 'HonorDXGI' = 0; 'Behavior' = $null; 'Mode' = 0; 'HonorUser' = 0 }; 'WindowsDefault' = @{ 'HonorDXGI' = $null; 'Behavior' = $null; 'Mode' = $null; 'HonorUser' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableFullscreenOptims', 'EnableFullscreenOptims')
    }
    @{
      Id = 'windows.uac-admin-consent'
      Name = 'UAC administrator consent prompt policy'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Security'
      Description = 'Represent the two legacy UAC values as one user choice. NoPrompt elevates administrators without consent; SecureConsent prompts on the secure desktop for non-Windows binaries. Does not change EnableLUA, standard-user elevation, or provision an elevated process. Optional security policy with explicit tradeoffs. One state changes all declared values together; partial failures retain the complete pre-change record. WindowsDefault removes all overrides. Saved-run restore preserves individual prior values/types and unrelated data. No UI refresh or restart occurs.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      RegistryValues = @(@{ 'Key' = 'Consent'; 'RegistryPath' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; 'ValueName' = 'ConsentPromptBehaviorAdmin'; 'ValueType' = 'DWord' }, @{ 'Key' = 'SecureDesktop'; 'RegistryPath' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; 'ValueName' = 'PromptOnSecureDesktop'; 'ValueType' = 'DWord' })
      States = @{ 'NoPrompt' = @{ 'Consent' = 0; 'SecureDesktop' = 0 }; 'SecureConsent' = @{ 'Consent' = 5; 'SecureDesktop' = 1 }; 'WindowsDefault' = @{ 'Consent' = $null; 'SecureDesktop' = $null } }
      BaselineState = 'WindowsDefault'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('SetUACLow', 'SetUACHigh')
    }
    @{
      Id = 'windows.content-delivery'
      Name = 'App suggestions: content delivery permission (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write the legacy ContentDeliveryAllowed preference for the current user. This was the broad content-delivery switch in DisableAppSuggestions; it is not a documented master switch for every Windows advertisement. Disabled writes 0; Enabled writes 1. The Microsoft link explains Spotlight features, not this registry mapping. Current Windows 11 behavior remains unverified.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'ContentDeliveryAllowed'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.oem-preinstalled-app-suggestions'
      Name = 'App suggestions: OEM app promotion (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write OemPreInstalledAppsEnabled, the OEM-specific app preference included in the legacy app-suggestions bundle. Disabled writes 0; Enabled writes 1. Its name suggests OEM app promotion, but that interpretation and current Windows 11 effect are unverified. Does not uninstall existing OEM apps. Microsoft documents the feature area, not this value.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'OemPreInstalledAppsEnabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.preinstalled-app-suggestions'
      Name = 'App suggestions: preinstalled app promotion (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write PreInstalledAppsEnabled, a preinstalled-app preference from the legacy app-suggestions bundle, distinct from its OEM preference. Disabled writes 0; Enabled writes 1. Its name suggests preinstalled app promotion; the exact current behavior is unverified. Does not remove apps or change historical PreInstalledAppsEverEnabled bookkeeping. Microsoft documents the feature area, not this value.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'PreInstalledAppsEnabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.silent-app-installation'
      Name = 'App suggestions: silent suggested-app installation (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write SilentInstalledAppsEnabled, the legacy preference intended to permit or suppress automatic installation of suggested apps. Disabled writes 0; Enabled writes 1. Does not remove apps already installed or prevent every Store or Windows Update installation. The intended purpose follows the legacy selector and value name; the Microsoft feature reference does not verify this mapping on current Windows 11.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SilentInstalledAppsEnabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.suggested-content-310093'
      Name = 'App suggestions: unresolved channel 310093 (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write only SubscribedContent-310093Enabled from the legacy app-suggestions bundle: Disabled=0, Enabled=1. Legacy EnableAppSuggestions removed this value instead; use WindowsDefault for that behavior. Microsoft''s HOBL preparation sample includes this value among notification-suppression writes, without identifying the exact notification. The Microsoft link is Spotlight feature background, not documentation of channel 310093. Exact purpose and current effect are unresolved; exclude from recommended profiles until evaluated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SubscribedContent-310093Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.suggested-content-314559'
      Name = 'App suggestions: unresolved channel 314559 (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write only SubscribedContent-314559Enabled from the legacy app-suggestions bundle: Disabled=0, Enabled=1. Legacy EnableAppSuggestions removed this value instead; use WindowsDefault for that behavior. No primary reference reviewed identifies a distinct user-visible feature for this channel. The Microsoft link is Spotlight feature background, not documentation of channel 314559. Exact purpose and current effect are unresolved; exclude from recommended profiles until evaluated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SubscribedContent-314559Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.suggested-content-338387'
      Name = 'App suggestions: unresolved channel 338387 (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write only SubscribedContent-338387Enabled from the legacy app-suggestions bundle: Disabled=0, Enabled=1. Legacy EnableAppSuggestions removed this value instead; use WindowsDefault for that behavior. No primary reference reviewed identifies a distinct user-visible feature for this channel. The Microsoft link is Spotlight feature background, not documentation of channel 338387. Exact purpose and current effect are unresolved; exclude from recommended profiles until evaluated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SubscribedContent-338387Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.suggested-content-338388'
      Name = 'App suggestions: unresolved channel 338388 (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write only SubscribedContent-338388Enabled from the legacy app-suggestions bundle: Disabled=0, Enabled=1. Legacy EnableAppSuggestions wrote 1 to this value. No primary reference reviewed identifies a distinct user-visible feature for this channel. The Microsoft link is Spotlight feature background, not documentation of channel 338388. Exact purpose and current effect are unresolved; exclude from recommended profiles until evaluated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SubscribedContent-338388Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.suggested-content-338389'
      Name = 'App suggestions: unresolved channel 338389 (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write only SubscribedContent-338389Enabled from the legacy app-suggestions bundle: Disabled=0, Enabled=1. Legacy EnableAppSuggestions wrote 1 to this value. Microsoft''s HOBL preparation sample includes this value among notification-suppression writes, without identifying the exact notification. The Microsoft link is Spotlight feature background, not documentation of channel 338389. Exact purpose and current effect are unresolved; exclude from recommended profiles until evaluated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SubscribedContent-338389Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.suggested-content-338393'
      Name = 'App suggestions: unresolved channel 338393 (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write only SubscribedContent-338393Enabled from the legacy app-suggestions bundle: Disabled=0, Enabled=1. Legacy EnableAppSuggestions removed this value instead; use WindowsDefault for that behavior. No primary reference reviewed identifies a distinct user-visible feature for this channel. The Microsoft link is Spotlight feature background, not documentation of channel 338393. Exact purpose and current effect are unresolved; exclude from recommended profiles until evaluated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SubscribedContent-338393Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.suggested-content-353694'
      Name = 'App suggestions: unresolved channel 353694 (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write only SubscribedContent-353694Enabled from the legacy app-suggestions bundle: Disabled=0, Enabled=1. Legacy EnableAppSuggestions wrote 1 to this value. No primary reference reviewed identifies a distinct user-visible feature for this channel. The Microsoft link is Spotlight feature background, not documentation of channel 353694. Exact purpose and current effect are unresolved; exclude from recommended profiles until evaluated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SubscribedContent-353694Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.suggested-content-353696'
      Name = 'App suggestions: unresolved channel 353696 (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write only SubscribedContent-353696Enabled from the legacy app-suggestions bundle: Disabled=0, Enabled=1. Legacy EnableAppSuggestions wrote 1 to this value. No primary reference reviewed identifies a distinct user-visible feature for this channel. The Microsoft link is Spotlight feature background, not documentation of channel 353696. Exact purpose and current effect are unresolved; exclude from recommended profiles until evaluated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SubscribedContent-353696Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.suggested-content-353698'
      Name = 'App suggestions: unresolved channel 353698 (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write only SubscribedContent-353698Enabled from the legacy app-suggestions bundle: Disabled=0, Enabled=1. Legacy EnableAppSuggestions removed this value instead; use WindowsDefault for that behavior. No primary reference reviewed identifies a distinct user-visible feature for this channel. The Microsoft link is Spotlight feature background, not documentation of channel 353698. Exact purpose and current effect are unresolved; exclude from recommended profiles until evaluated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SubscribedContent-353698Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.settings-pane-suggestions'
      Name = 'App suggestions: Settings pane promotion (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write the legacy SystemPaneSuggestionsEnabled preference: Disabled=0 or Enabled=1. Intended area is suggestions in Settings, separate from the numbered subscription channels. Microsoft documents the visible suggested-content option under Privacy & security > Recommendations & offers (General on older builds), but not a one-to-one mapping to this value. Current effect requires a Settings UI comparison.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/privacy/privacy-settings-for-recommendations-offers-in-windows-11'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      ValueName = 'SystemPaneSuggestionsEnabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.post-setup-suggestions'
      Name = 'App suggestions: finish-setting-up prompts (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write ScoobeSystemSettingEnabled, intended to control prompts to finish setting up Windows and Microsoft services. Disabled writes 0; Enabled writes 1; legacy EnableAppSuggestions instead removed this value, reproduced by WindowsDefault. Microsoft documents notification and welcome options, not this value. Current prompt behavior remains unverified; this does not configure or disable all app suggestions.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/notifications-and-do-not-disturb-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement'
      ValueName = 'ScoobeSystemSettingEnabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.implicit-text-personalization'
      Name = 'Input personalization: typed-word learning (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write RestrictImplicitTextCollection from the legacy Cortana bundle: Restricted=1, Allowed=0. Intended purpose is implicit learning from typed text for personalization, separate from handwriting and diagnostic uploads. The Microsoft reference explains the custom word list, not this individual mapping. Current effect is unverified; allowing this preference does not enable the retired Cortana app. Registry restore cannot recover a word list if Windows clears it.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/privacy/speech-voice-activation-inking-typing-and-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\InputPersonalization'
      ValueName = 'RestrictImplicitTextCollection'
      ValueType = 'DWord'
      States = @{ Restricted = 1; Allowed = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.implicit-ink-personalization'
      Name = 'Input personalization: handwriting learning (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write RestrictImplicitInkCollection from the legacy Cortana bundle: Restricted=1, Allowed=0. Intended purpose is implicit learning from handwriting for personalization, separate from typed text and diagnostic uploads. The Microsoft reference explains the custom word list, not this individual mapping. Current effect is unverified; allowing this preference does not enable the retired Cortana app. Registry restore cannot recover learned data if Windows clears it.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/privacy/speech-voice-activation-inking-typing-and-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\InputPersonalization'
      ValueName = 'RestrictImplicitInkCollection'
      ValueType = 'DWord'
      States = @{ Restricted = 1; Allowed = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.input-personalization-contact-harvesting'
      Name = 'Input personalization: contact-name learning (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write HarvestContacts in the legacy input-personalization training store: Disabled=0, Enabled=1. Its name suggests using contact names to improve personalization; this interpretation and current Windows 11 effect are unverified. Legacy EnableCortana removed the value instead, reproduced by WindowsDefault. This is not the app contacts-access policy and does not enable Cortana. Microsoft documents personalization behavior, not this value.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/privacy/speech-voice-activation-inking-typing-and-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore'
      ValueName = 'HarvestContacts'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.diagnostic-data-policy'
      Name = 'Windows diagnostic data level'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Select diagnostic data policy level. Off is honored only on supported Enterprise, Education and IoT editions; other editions collect at least required data. Optional enables optional diagnostics. No scheduled tasks, services, Office policies or non-policy mirror values are changed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#allowtelemetry'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
      ValueName = 'AllowTelemetry'
      ValueType = 'DWord'
      States = @{ Off = 0; Required = 1; Optional = 3; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Without this policy Windows collects required diagnostics; optional collection follows setup and user choices, subject to edition and other policies' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.linguistic-data-collection-policy'
      Name = 'Improve inking and typing recognition'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Control sending inking and typing recognition data to Microsoft. Supported policy editions are Pro, Enterprise, Education and IoT Enterprise. Separate from local input personalization and the existing inking-typing-data operation.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-textinput#allowlinguisticdatacollection'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput'
      ValueName = 'AllowLinguisticDataCollection'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'No machine override; collection follows the user recognition-data preference and applicable policy' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.feedback-notifications-policy'
      Name = 'Windows feedback notifications'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Suppress feedback notifications or allow Windows to request feedback. Policy support requires Pro, Enterprise, Education or IoT Enterprise. No SIUF frequency overrides or scheduled-task changes.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience#donotshowfeedbacknotifications'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
      ValueName = 'DoNotShowFeedbackNotifications'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Allowed = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Feedback requests are permitted; frequency follows user preferences' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.error-reporting'
      Name = 'Windows Error Reporting preference'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Control the documented machine Windows Error Reporting preference. Policy may take precedence. No queue deletion or scheduled-task changes; restoring the preference does not recover reports discarded by Windows.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/wer/wer-settings'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
      ValueName = 'Disabled'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Error reporting is enabled unless overridden by policy or another reporting preference' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.ncsi-active-probing'
      Name = 'Network connectivity active probing'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Control the legacy active connectivity probing preference. Disabling can affect network-status detection and applications. Microsoft documents connectivity probing; registry behavior and network results require separate target review. No adapter or firewall changes.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#14-network-connection-status-indicator'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet'
      ValueName = 'EnableActiveProbing'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.msrt-update-offering'
      Name = 'Malicious Software Removal Tool update offering'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System behavior'
      Description = 'Control the legacy preference for MSRT offers through Windows Update. Microsoft documents the tool and update behavior, not this value; current offering behavior requires review. Does not disable antivirus or run a malware scan.'
      DocumentationUri = 'https://support.microsoft.com/en-us/servicing/os/windows/2021/01/remove-specific-prevalent-malware-with-windows-malicious-software-removal-tool-kb890830'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\MRT'
      ValueName = 'DontOfferThroughWUAU'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Allowed = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows Update may offer applicable MSRT releases' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.update-driver-policy'
      Name = 'Drivers in Windows quality updates'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System behavior'
      Description = 'Exclude or include drivers in Windows quality updates on supported Pro, Enterprise, Education and IoT Enterprise editions. Does not block manually installed drivers, device metadata or driver searches.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#excludewudriversinqualityupdate'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
      ValueName = 'ExcludeWUDriversInQualityUpdate'
      ValueType = 'DWord'
      States = @{ Excluded = 1; Included = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows quality updates include applicable driver-classified updates' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.device-metadata-downloads'
      Name = 'Device metadata application downloads'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System behavior'
      Description = 'Prevent automatic downloading of applications associated with device metadata, or leave the decision to Device Installation Settings. Requires a supported policy edition. Does not itself block Windows Update driver packages.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceinstallation#preventdevicemetadatafromnetwork'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'
      ValueName = 'PreventDeviceMetadataFromNetwork'
      ValueType = 'DWord'
      States = @{ Prevented = 1; UserChoice = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Device Installation Settings controls metadata application downloads' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.update-download-mode'
      Name = 'Automatic Updates download preference'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System behavior'
      Description = 'Choose notification before download or automatic download with notification before installation. Other Automatic Updates policies, including NoAutoUpdate, and modern update policies can take precedence. No update service changes or forced installation.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
      ValueName = 'AUOptions'
      ValueType = 'DWord'
      States = @{ NotifyDownload = 2; AutoDownload = 3; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Automatic Updates follows existing user or administrator preferences and other update policies' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.automatic-restart-sign-on'
      Name = 'Automatic restart sign-on'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System behavior'
      Description = 'Control automatic sign-in and locking of the last interactive user after restart. Policy requires a supported edition; BitLocker and device-join state affect behavior. Does not restart, sign in or unlock a user.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#allowautomaticrestartsignon'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      ValueName = 'DisableAutomaticRestartSignOn'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Automatic restart sign-on and lock is allowed, subject to BitLocker and device-join requirements' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.storage-sense'
      Name = 'Storage Sense user preference'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System behavior'
      Description = 'Control only the legacy Storage Sense enablement preference. Microsoft documents cleanup behavior, not this registry value; target review is required. Enabling may allow Windows to delete eligible content later. No cleanup runs, StoragePoliciesNotified writes or recursive deletion of other preferences. Restoring the value cannot recover deleted files.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/manage-drive-space-with-storage-sense'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
      ValueName = '01'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.recycle-bin-policy'
      Name = 'Move deleted files to the Recycle Bin'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System behavior'
      Description = 'Choose whether Explorer permanently deletes files instead of moving them to the Recycle Bin. Requires a supported policy edition. RIDE does not delete files; restoring the policy cannot recover files later deleted by Windows.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer#norecyclefiles'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
      ValueName = 'NoRecycleFiles'
      ValueType = 'DWord'
      States = @{ Bypass = 1; UseRecycleBin = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Explorer places eligible deleted files in the Recycle Bin' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.lock-screen-policy'
      Name = 'Display the lock screen'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control the lock-screen display policy on supported editions. Does not remove authentication, disable locking or implement the legacy RS1 scheduled-task workaround. No restart or sign-out.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_nolockscreen'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
      ValueName = 'NoLockScreen'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows displays the lock screen when applicable' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.verbose-logon-status'
      Name = 'Verbose startup and shutdown status'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control verbose startup, shutdown, logon and logoff messages. Other status-message policies can override this option. No restart or sign-out; visible behavior requires a separate boot scenario.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-logon#verbosestatus'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      ValueName = 'VerboseStatus'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows displays its ordinary status messages' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.linked-mapped-drives'
      Name = 'Mapped drives across linked UAC sessions'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Allow mapped drives to be shared between linked UAC logon sessions. Restart may be required. Does not change UAC consent settings or share connections between unrelated credentials. No drive mapping or restart.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      ValueName = 'EnableLinkedConnections'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Linked UAC logon sessions do not share mapped-drive links through this override' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.attachment-zone-information'
      Name = 'Preserve zone information on downloaded attachments'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Choose whether Attachment Manager preserves source-zone information on saved attachments. Discard can weaken later security checks. Requires a supported policy edition. Does not remove existing zone metadata or disable SmartScreen.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-attachmentmanager#donotpreservezoneinformation'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
      ValueName = 'SaveZoneInformation'
      ValueType = 'DWord'
      States = @{ Discard = 1; Preserve = 2; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Attachment Manager preserves zone information on supported file systems' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.desktop-recycle-bin-icon'
      Name = 'Recycle Bin desktop icon'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Control one Windows 11 desktop namespace icon using the legacy NewStartPanel value. Microsoft documents the visible icon option, not this registry mapping. ClassicStartMenu writes are excluded on this target; visual behavior requires review. The separate all-icons visibility preference can hide this icon. No shortcut deletion or shell restart.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
      ValueName = '{645FF040-5081-101B-9F08-00AA002F954E}'
      ValueType = 'DWord'
      States = @{ Shown = 0; Hidden = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.desktop-this-pc-icon'
      Name = 'This PC desktop icon'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Control one Windows 11 desktop namespace icon using the legacy NewStartPanel value. Microsoft documents the visible icon option, not this registry mapping. ClassicStartMenu writes are excluded on this target; visual behavior requires review. The separate all-icons visibility preference can hide this icon. No shortcut deletion or shell restart.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
      ValueName = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'
      ValueType = 'DWord'
      States = @{ Shown = 0; Hidden = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.desktop-user-files-icon'
      Name = 'User files desktop icon'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Control one Windows 11 desktop namespace icon using the legacy NewStartPanel value. Microsoft documents the visible icon option, not this registry mapping. ClassicStartMenu writes are excluded on this target; visual behavior requires review. The separate all-icons visibility preference can hide this icon. No shortcut deletion or shell restart.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
      ValueName = '{59031a47-3f72-44a7-89c5-5595fe6b30ee}'
      ValueType = 'DWord'
      States = @{ Shown = 0; Hidden = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.desktop-control-panel-icon'
      Name = 'Control Panel desktop icon'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Control one Windows 11 desktop namespace icon using the legacy NewStartPanel value. Microsoft documents the visible icon option, not this registry mapping. ClassicStartMenu writes are excluded on this target; visual behavior requires review. The separate all-icons visibility preference can hide this icon. No shortcut deletion or shell restart.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
      ValueName = '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}'
      ValueType = 'DWord'
      States = @{ Shown = 0; Hidden = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.desktop-network-icon'
      Name = 'Network desktop icon'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Control one Windows 11 desktop namespace icon using the legacy NewStartPanel value. Microsoft documents the visible icon option, not this registry mapping. ClassicStartMenu writes are excluded on this target; visual behavior requires review. The separate all-icons visibility preference can hide this icon. No shortcut deletion or shell restart.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
      ValueName = '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}'
      ValueType = 'DWord'
      States = @{ Shown = 0; Hidden = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.desktop-build-number'
      Name = 'Windows build number on the desktop'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Control the legacy desktop version-label preference. Microsoft documents system version discovery, not this registry mapping; desktop rendering requires target review and may need a new sign-in. No reboot or shell restart.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#system---about'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\Desktop'
      ValueName = 'PaintDesktopVersion'
      ValueType = 'DWord'
      States = @{ Shown = 1; Hidden = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal default and effective behavior depend on the Windows build, image, user preferences and policy; verify on the target' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.lock-screen-network-selection'
      Name = 'Network selection on the sign-in screen'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control network selection before sign-in. Policy support requires Windows 11 Pro, Enterprise, Education or IoT Enterprise; this does not disable network adapters.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#dontdisplaynetworkselectionui'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
      ValueName = 'DontDisplayNetworkSelectionUI'
      ValueType = 'DWord'
      States = @{ Hidden = 1; Shown = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Network selection is available before sign-in when this policy is not configured' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.shutdown-without-logon'
      Name = 'Shutdown from the sign-in screen'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Allow or prevent shutdown from the sign-in screen. This does not change signed-in users'' shutdown rights or initiate shutdown.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#shutdown_allowsystemtobeshutdownwithouthavingtologon'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      ValueName = 'ShutdownWithoutLogon'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 1; EffectiveDefault = 'Shutdown without sign-in is enabled on Windows client installations' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.title-bar-shake'
      Name = 'Title bar window shake'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control the title bar shake preference for minimizing other windows. Microsoft documents the visible option; the DisallowShaking mapping comes from the legacy selectors and requires visible-behavior review after sign-in. RIDE does not restart Explorer.'
      DocumentationUri = 'https://support.microsoft.com/en-gb/accessibility/windows/make-it-easier-to-focus-on-tasks'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'DisallowShaking'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The preference depends on the Windows image and user customization; verify the Multitasking option' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.start-recently-added-apps'
      Name = 'Recently added applications in Start'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Hide recently added apps in Start, or leave visibility to user preferences. Policy support requires Windows 11 Pro, Enterprise, Education or IoT Enterprise. A restart may be needed; RIDE does not restart the device.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start#hiderecentlyaddedapps'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
      ValueName = 'HideRecentlyAddedApps'
      ValueType = 'DWord'
      States = @{ Hidden = 1; UserChoice = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'No policy override; visibility is controlled by the user''s Start preferences' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.title-bar-accent-color'
      Name = 'Accent color on title bars and borders'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control accent color on title bars and window borders for the current user. Application theme support and high-contrast settings can affect rendering; reopening applications or signing in again may be needed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#personalization---colors'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\DWM'
      ValueName = 'ColorPrevalence'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The literal value depends on the image/theme; title bar accent coloring is normally off' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.app-color-mode'
      Name = 'Application light or dark mode'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Select the current-user light or dark preference for applications that honor Windows theme settings. Individual app preferences and high-contrast themes can take precedence; RIDE does not restart apps.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#personalization---colors'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
      ValueName = 'AppsUseLightTheme'
      ValueType = 'DWord'
      States = @{ Dark = 0; Light = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Application mode follows the installed theme and user customization; no universal literal default' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.system-color-mode'
      Name = 'Windows light or dark mode'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Select the current-user light or dark preference for Windows surfaces. This is separate from application color mode; Windows may require a new sign-in to refresh the shell.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#personalization---colors'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
      ValueName = 'SystemUsesLightTheme'
      ValueType = 'DWord'
      States = @{ Dark = 0; Light = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Windows mode follows the installed theme and user customization; no universal literal default' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.sound-scheme-change-policy'
      Name = 'Changing the sound scheme'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Allow or prevent the current user from changing the sound scheme. This corrects the legacy HKLM write to the documented HKCU policy. Policy support requires Pro, Enterprise, Education or IoT Enterprise. It does not change the selected scheme or mute audio.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_nosoundschemeui'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: changing the sound scheme'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Control Panel > Sound > Sounds > Sound Scheme'
        GuiEffect = 'Blocked prevents changing the sound scheme. Allowed and WindowsDefault permit changes subject to other applicable policy; the selected scheme is preserved.'
        Requirements = @('Windows 11 21H2 or later: Pro, Enterprise, Education or IoT Enterprise', 'Local user policy; RIDE does not require Intune, a cloud account or paid membership')
        OtherSupportedChoices = @('Microsoft documents user scope; RIDE implements that scope. Selecting a scheme and muting audio are separate controls')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_nosoundschemeui')
      }
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Policies\Microsoft\Windows\Personalization'
      ValueName = 'NoChangingSoundScheme'
      ValueType = 'DWord'
      States = @{ Blocked = 1; Allowed = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users may change the sound scheme when the policy is not configured' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.taskbar-alignment'
      Name = 'Taskbar alignment'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Align the current-user Windows 11 taskbar left or center. Microsoft documents the visible option; the TaskbarAl mapping comes from the legacy selectors and requires visible-behavior review. RIDE does not restart Explorer.'
      DocumentationUri = 'https://support.microsoft.com/en-gb/accessibility/windows/make-it-easier-to-focus-on-tasks'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'TaskbarAl'
      ValueType = 'DWord'
      States = @{ Left = 0; Centered = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'The taskbar is normally centered; the literal value depends on the image and user profile' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.sensors-policy'
      Name = 'Windows sensors policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Allow or block use of the Windows sensor feature by programs. Policy support requires Pro, Enterprise, Education or IoT Enterprise; this does not uninstall sensor devices.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-sensors#disablesensors_2'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
      ValueName = 'DisableSensors'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Allowed = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Programs can use available sensors when this policy is not configured' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.biometrics-policy'
      Name = 'Windows Biometric Framework policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Allow or block the Windows Biometric Framework. Microsoft documents policy-controlled enablement; the registry mapping is confirmed by Windows Biometrics.admx, not this API reference. This does not enroll biometrics, remove templates or change separate domain sign-in policies. Hardware behavior needs separate verification.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winbio/nf-winbio-winbiogetenabledsetting'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics'
      ValueName = 'Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Allowed = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'The framework is allowed by built-in policy; hardware and other sign-in policies still apply' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.app-camera-policy'
      Name = 'Windows application camera access policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Select the default Windows-app camera policy. Per-app policies take precedence; this is not a global hardware switch for all desktop programs. Requires Pro, Enterprise, Education or IoT Enterprise. Reopen affected apps or restart to refresh the policy.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesscamera'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessCamera'
      ValueType = 'DWord'
      States = @{ ForceDeny = 2; ForceAllow = 1; UserControl = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'User consent controls supported apps unless a per-app policy overrides it' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.app-microphone-policy'
      Name = 'Windows application microphone access policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Select the default Windows-app microphone policy. Per-app policies take precedence; this is not a global hardware switch for all desktop programs. Requires Pro, Enterprise, Education or IoT Enterprise. Reopen affected apps or restart to refresh the policy.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessmicrophone'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessMicrophone'
      ValueType = 'DWord'
      States = @{ ForceDeny = 2; ForceAllow = 1; UserControl = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'User consent controls supported apps unless a per-app policy overrides it' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.delivery-optimization-download-mode'
      Name = 'Delivery Optimization download mode'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Choose HTTP-only downloads without peering, LAN peers, or internet peers for Delivery Optimization. Windows Update continues to function. HttpOnly=0 replaces the legacy Bypass=100 mode, deprecated on Windows 11; LocalNetwork=1 is now explicit rather than removing policy. No updates are triggered.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-reference'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
      ValueName = 'DODownloadMode'
      ValueType = 'DWord'
      States = @{ HttpOnly = 0; LocalNetwork = 1; Internet = 3; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'LAN peering mode 1 is the documented default when no policy overrides the device' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.clear-recent-documents-on-exit'
      Name = 'Clear recent documents at sign-out'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Control clearing of recent document shortcuts and unpinned Jump List history at sign-out. This corrects the legacy HKLM write to the documented user policy. Other history policies can take precedence. Exact restore covers the policy value, not history Windows later deletes. RIDE does not sign out or clear files.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-startmenu#clearrecentdocsonexit'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
      ValueName = 'ClearRecentDocsOnExit'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Recent-document shortcuts are retained at sign-out when the policy is not configured' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.recent-document-history-policy'
      Name = 'Recent document history policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Allow or prevent Windows recent-document history. The linked history reference describes related behavior; the machine NoRecentDocsHistory mapping is confirmed by Windows StartMenu.admx and retained for behavior review. This is separate from Explorer recent shortcuts and application-owned history. Restore recovers the policy, not missed or cleared history.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-startmenu#clearrecentdocsonexit'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
      ValueName = 'NoRecentDocsHistory'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Allowed = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows can retain recent-document history unless policy or user preferences prevent it' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.fast-startup'
      Name = 'Fast startup local preference'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Services'
      Description = 'Control the local Fast startup preference. Effective use requires hibernation and compatible hardware and can be overridden by the Require use of fast startup policy. This operation does not enable hibernation, create a hibernation file, or restart/shut down the device.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/unified-write-filter/hibernate-once-resume-many-horm#how-to-disable-fast-startup'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
      ValueName = 'HiberbootEnabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Fast startup is normally enabled when supported; the literal and effective defaults depend on the image, hibernation and policy' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.auto-reboot-on-crash'
      Name = 'Automatic restart after a system failure'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Services'
      Description = 'Control automatic restart during system-failure recovery. This does not generate a crash or change dump settings; a restart may be needed before the preference takes effect.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-osrecoveryconfiguration'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
      ValueName = 'AutoReboot'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 1; EffectiveDefault = 'Automatic restart is enabled on standard Windows 11 installations' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.clipboard-history'
      Name = 'Clipboard history preference'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Services'
      Description = 'Control the current-user clipboard history preference without enabling cross-device synchronization. Microsoft documents feature behavior; the registry mapping comes from the legacy selectors and requires behavior review. Separate policies can prevent history. Restore recovers the preference, not clipboard contents.'
      DocumentationUri = 'https://support.microsoft.com/en-US/Windows/Apps/using-the-clipboard'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Clipboard'
      ValueName = 'EnableClipboardHistory'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Clipboard history is opt-in and normally disabled; the literal default depends on the image and user profile' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.navigation-pane-libraries'
      Name = 'Libraries in Explorer navigation pane'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show or hide the Libraries namespace in the current-user Explorer navigation pane. Microsoft documents namespace pinning; the CLSID registry mapping comes from the legacy selectors and requires visible-behavior review. Libraries and their files are preserved. RIDE does not restart Explorer.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/desktop/properties/props-system-ispinnedtonamespacetree'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}'
      ValueName = 'System.IsPinnedToNameSpaceTree'
      ValueType = 'DWord'
      States = @{ Shown = 1; Hidden = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'No per-user Libraries pinning override; shell registration and navigation preferences determine visibility' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.god-mode-shortcut'
      Name = 'God Mode desktop shortcut'
      Kind = 'ShellFolder'
      Category = 'Windows settings / Explorer'
      Description = 'Create or remove the current-user God Mode desktop folder shortcut to the All Tasks Control Panel view. This only adds convenient access to existing settings. Removal refuses nonempty folders, files and reparse points. Shell rendering remains subject to Windows build behavior.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction'
      ReferenceUri = 'https://www.tomshardware.com/how-to/enable-god-mode-windows-11'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ShellFolder'
      PathResolver = 'CurrentUserDesktop'
      FolderName = 'GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}'
      States = @{ Present = 'Present'; Absent = 'Absent' }
      BaselineState = 'Absent'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Windows does not create this desktop shortcut by default' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.empty-drives-visibility'
      Name = 'Empty drives visibility in Explorer'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show or hide drives with no media in File Explorer, or remove the current-user override. This does not hide drives containing data or change drive access. Microsoft documents the folder option; the HideDrivesWithNoMedia registry mapping is retained from the legacy selectors for review.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'HideDrivesWithNoMedia'
      ValueType = 'DWord'
      States = @{ Visible = 0; Hidden = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 1; EffectiveDefault = 'Drives with no media are hidden by default in File Explorer' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.folder-merge-conflicts'
      Name = 'Folder merge conflict prompts'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show or hide folder merge conflict prompts in File Explorer, or remove the current-user override. This controls folder merge prompts, not the separate behavior for duplicate files. Microsoft documents the folder option; the HideMergeConflicts registry mapping is retained from the legacy selectors for review.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'HideMergeConflicts'
      ValueType = 'DWord'
      States = @{ Shown = 0; Hidden = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 1; EffectiveDefault = 'Folder merge conflict prompts are hidden by default; duplicate-file prompts are separate' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.navigation-pane-all-folders'
      Name = 'All folders in Explorer navigation pane'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Enable or disable Show all folders in the current user File Explorer navigation pane, or remove its override. This does not change the separate auto-expand preference. Microsoft documents the folder option; the NavPaneShowAllFolders registry mapping is retained from the legacy selectors for review.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'NavPaneShowAllFolders'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'The navigation pane shows its standard entries unless Show all folders is enabled' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.explorer-title-full-path'
      Name = 'Full path in Explorer title bar'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show the full folder path in the File Explorer title bar, show only the folder name, or remove the current-user override. Newly opened windows may be needed to reflect the change.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState'
      ValueName = 'FullPath'
      ValueType = 'DWord'
      States = @{ Shown = 1; Hidden = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Only the folder name appears in the title bar unless the user enables the full path' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.protected-files-visibility'
      Name = 'Protected operating system files visibility'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show or hide protected operating system files in File Explorer, or remove the current-user override. Visibility also depends on the separate hidden-files setting; this operation does not change file attributes or permissions.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'ShowSuperHidden'
      ValueType = 'DWord'
      States = @{ Visible = 1; Hidden = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 0; EffectiveDefault = 'Protected operating system files are hidden by default' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.explorer-separate-process'
      Name = 'Explorer folder windows in a separate process'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Enable or disable the current-user option to launch folder windows in a separate process, or remove its override. RIDE does not restart Explorer; process behavior must be checked after reopening folder windows.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'SeparateProcess'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 0; EffectiveDefault = 'The separate-process folder option is disabled by default' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.restore-folder-windows'
      Name = 'Restore folder windows at logon'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Enable or disable the current-user preference to restore previous folder windows at logon, or remove its override. RIDE does not sign out or restart applications; actual restoration depends on the Windows build and sign-in settings.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'PersistBrowsers'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Folder-window restoration is opt-in; Windows sign-in settings can also enable this preference' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.sharing-wizard'
      Name = 'Explorer Sharing Wizard'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Enable or disable the Sharing Wizard option in File Explorer, or remove the current-user override. This changes the sharing interface preference; it does not create shares or alter existing permissions.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/a6ca3a17-1971-4b22-bf3b-e1a5d5c50fca'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'SharingWizardOn'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 1; EffectiveDefault = 'The Sharing Wizard option is enabled by default' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.item-selection-checkboxes'
      Name = 'Explorer item selection checkboxes'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show or hide item selection checkboxes in File Explorer, or remove the current-user override. The AutoCheckSelect mapping is retained from the legacy selectors for review; Microsoft documents the user-visible option rather than this registry value. Touch-oriented behavior may override the preference.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'AutoCheckSelect'
      ValueType = 'DWord'
      States = @{ Shown = 1; Hidden = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 0; EffectiveDefault = 'Item selection checkboxes are normally off; touch-oriented behavior can display them' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.thumbnail-display'
      Name = 'Explorer thumbnail display'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Allow thumbnail display or request icons only in File Explorer, or remove the current-user override. Thumbnail availability also depends on view size, providers and other policies. This does not modify or clear the thumbnail cache.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/a6ca3a17-1971-4b22-bf3b-e1a5d5c50fca'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'IconsOnly'
      ValueType = 'DWord'
      States = @{ Enabled = 0; Disabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 0; EffectiveDefault = 'Explorer allows thumbnails by default when a thumbnail provider and view support them' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.edge-friendly-url-format'
      Name = 'Edge copied URL format'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Windows Configuration'
      Description = 'Choose plain-text or titled hyperlink copying in Edge for the current user, or remove the policy override. Edge may require restart to reflect the policy.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/configurefriendlyurlformat'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
      ValueName = 'ConfigureFriendlyURLFormat'
      ValueType = 'DWord'
      States = @{ PlainText = 1; TitledHyperlink = 3; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Edge user preference controls copied URLs when no policy is configured' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.start-run-as-different-user'
      Name = 'Run as different user on Start'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Windows Configuration'
      Description = 'Show the Run as different user command on Start for applications that support it. Uses the documented current-user policy instead of the legacy machine-hive write; other Run as methods remain available.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-startmenu#showrunasdifferentuserinstart'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
      ValueName = 'ShowRunAsDifferentUserInStart'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Run as different user is hidden on Start without an enabled policy' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.background-apps-policy'
      Name = 'Background apps policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the device App Privacy policy that denies background access to Windows apps, or remove that policy override. Removing the policy does not clear per-app background access values in the current user profile.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsRunInBackground'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control background access when the App Privacy policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-voice-activation'
      Name = 'App voice activation permission'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write LetAppsActivateWithVoice=2 to force-deny voice activation for apps covered by this App Privacy policy, or remove the policy override. This is the general permission; activation while the device is locked has its own policy. It is not a microphone or universal speech-recognition switch.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsactivatewithvoice'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsActivateWithVoice'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-voice-activation-above-lock'
      Name = 'App voice activation while locked'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write LetAppsActivateWithVoiceAboveLock=2 to force-deny covered apps from activating by voice while the device is locked, or remove the policy override. General app voice activation is a separate permission and can still prevent activation. This does not unlock the device or grant microphone access.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsactivatewithvoiceabovelock'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsActivateWithVoiceAboveLock'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-notifications-access'
      Name = 'Notifications access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessNotifications'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-account-info-access'
      Name = 'Account info access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessAccountInfo'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-contacts-access'
      Name = 'Contacts access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessContacts'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-calendar-access'
      Name = 'Calendar access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessCalendar'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-phone-access'
      Name = 'Phone access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessPhone'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-call-history-access'
      Name = 'Call history access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessCallHistory'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-email-access'
      Name = 'Email access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessEmail'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-tasks-access'
      Name = 'Tasks access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessTasks'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-messaging-access'
      Name = 'Messaging access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessMessaging'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-radios-access'
      Name = 'Radios access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsAccessRadios'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-device-sync-access'
      Name = 'Device synchronization access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsSyncWithDevices'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-diagnostic-info-access'
      Name = 'Diagnostic info access for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the Windows App Privacy policy that denies this capability to all apps, or remove the policy override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
      ValueName = 'LetAppsGetDiagnosticInfo'
      ValueType = 'DWord'
      States = @{ Disabled = 2; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Users control app access when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-documents-library-access'
      Name = 'UWP documentsLibrary access'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the machine capability consent value for documentsLibrary access to Deny, Allow, or user controlled. Microsoft documents app capability behavior, not this specific legacy registry mapping.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/security/app-capability-declarations'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary'
      ValueName = 'Value'
      ValueType = 'String'
      States = @{ Denied = 'Deny'; Allowed = 'Allow'; UserControlled = $null }
      BaselineState = 'UserControlled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'User-controlled app access when no device-level value is set' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-pictures-library-access'
      Name = 'UWP picturesLibrary access'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the machine capability consent value for picturesLibrary access to Deny, Allow, or user controlled. Microsoft documents app capability behavior, not this specific legacy registry mapping.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/security/app-capability-declarations'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary'
      ValueName = 'Value'
      ValueType = 'String'
      States = @{ Denied = 'Deny'; Allowed = 'Allow'; UserControlled = $null }
      BaselineState = 'UserControlled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'User-controlled app access when no device-level value is set' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-videos-library-access'
      Name = 'UWP videosLibrary access'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the machine capability consent value for videosLibrary access to Deny, Allow, or user controlled. Microsoft documents app capability behavior, not this specific legacy registry mapping.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/security/app-capability-declarations'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary'
      ValueName = 'Value'
      ValueType = 'String'
      States = @{ Denied = 'Deny'; Allowed = 'Allow'; UserControlled = $null }
      BaselineState = 'UserControlled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'User-controlled app access when no device-level value is set' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-broad-file-system-access-access'
      Name = 'UWP broadFileSystemAccess access'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the machine capability consent value for broadFileSystemAccess to Deny, Allow, or user controlled. Microsoft documents app capability behavior, not this specific legacy registry mapping.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/security/app-capability-declarations'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess'
      ValueName = 'Value'
      ValueType = 'String'
      States = @{ Denied = 'Deny'; Allowed = 'Allow'; UserControlled = $null }
      BaselineState = 'UserControlled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'User-controlled app access when no device-level value is set' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-swap-file'
      Name = 'UWP swap file'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System'
      Description = 'Set the legacy SwapfileControl registry value to disable or re-enable the UWP swap file. A Windows restart is required. Microsoft documents UWP app lifecycle behavior but does not document this specific registry mapping.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/uwp/launch-resume/optimize-suspend-resume'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
      ValueName = 'SwapfileControl'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows manages the UWP swap file when SwapfileControl is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.uwp-background-app-user-overrides'
      Name = 'Per-app background access overrides'
      Kind = 'BackgroundAppOverrides'
      Category = 'Windows settings / Privacy'
      Description = 'Remove Disabled and DisabledByUser values from current-user background app entries. Applying captures existing values so a run can restore them exactly.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'BackgroundAppOverrides'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
      ValueNames = @('Disabled', 'DisabledByUser')
      States = @{ Reset = 'Reset' }
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'No per-app overrides'; EffectiveDefault = 'Background app access is governed by the device policy or each app preference when no per-app override values exist' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.show-known-extensions'
      Name = 'Show known file extensions'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show file extensions for registered file types in File Explorer for the current Windows execution user. The Microsoft reference documents the Windows 11 GUI behavior, not the HideFileExt registry mapping. This is a preference, not machine enforcement; current GUI round-trip and Server interface acceptance remain pending.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/common-file-name-extensions-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: File Explorer file-name extension visibility'
        Behavior = 'Preference'
        GuiPath = 'Windows 11 File Explorer > View > Show > File name extensions'
        GuiEffect = 'An ordinary Explorer preference; RIDE does not lock the GUI. Other applicable policies may restrict changes. Current GUI round-trip acceptance remains pending.'
        Requirements = @('File Explorer; GUI path describes Windows 11. Server GUI availability needs separate acceptance', 'Local preference; no separate account, cloud license or membership requirement')
        OtherSupportedChoices = @('This ID implements the current-user preference; it does not enforce a machine policy')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/common-file-name-extensions-in-windows')
      }
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'HideFileExt'
      ValueType = 'DWord'
      States = @{ Enabled = 0; Disabled = 1 }
      BaselineState = 'Disabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 1; EffectiveDefault = 'Disabled (known file extensions are hidden)' }
        'Windows Server 2025' = @{ DefaultValueExists = $true; DefaultValue = 1; EffectiveDefault = 'Disabled (known file extensions are hidden)' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.autoplay-policy'
      Name = 'Autoplay policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = "Set the current user's Autoplay preference."
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'
      ValueName = 'DisableAutoplay'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = 0 }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Enabled (AutoPlay is allowed by this preference)' }
        'Windows Server 2025' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Enabled (AutoPlay is allowed by this preference)' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.autorun-policy'
      Name = 'Autorun policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Set the machine policy for Autorun on removable and other drives.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
      ValueName = 'NoDriveTypeAutoRun'
      ValueType = 'DWord'
      States = @{ Disabled = 255; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows built-in AutoRun default mask: 0x91 (145)' }
        'Windows Server 2025' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows built-in AutoRun default mask: 0x91 (145)' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.script-host-policy'
      Name = 'Windows Script Host policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Set the Windows Script Host policy or restore its default value.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wscript'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
      ValueName = 'Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Enabled when this policy value is absent' }
        'Windows Server 2025' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Enabled when this policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.inking-typing-data'
      Name = 'Inking and typing data'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Stop sending the current user''s inking and typing data to Microsoft.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/privacy/windows-10-and-privacy-compliance'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\SOFTWARE\Microsoft\Input\TIPC'
      ValueName = 'Enabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows input-personalization behavior applies when no per-user override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.defender-tools-exclusion'
      Name = 'Defender tools directory exclusion'
      Kind = 'DefenderExclusion'
      Category = 'Windows settings / Security'
      Description = 'Add the configured tools directory to Microsoft Defender exclusions.'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'DefenderExclusion'
      PathResolver = 'ToolsDirectory'
      DocumentationUri = 'https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'No tools directory exclusion is declared by RIDE unless the profile requests it' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.defender-bootstrap-exclusion'
      Name = 'Defender bootstrap directory exclusion'
      Kind = 'DefenderExclusion'
      Category = 'Windows settings / Security'
      Description = 'Create the current user''s Downloads\bootstrap directory and add it to Microsoft Defender exclusions.'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'DefenderExclusion'
      PathResolver = 'BootstrapDirectory'
      DocumentationUri = 'https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'No bootstrap directory exclusion is declared by RIDE unless the profile requests it' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.proxy-autoconfig-url'
      Name = 'Automatic proxy configuration URL'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Clear the current user''s automatic proxy configuration URL override.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-proxy-server-settings'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
      ValueName = 'AutoconfigURL'
      ValueType = 'String'
      States = @{ Disabled = ''; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'No proxy auto-configuration URL override unless configured by the user or administrator' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.llmnr-policy'
      Name = 'LLMNR multicast name resolution policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Disable Link-Local Multicast Name Resolution through the Windows policy value set by the legacy DisableMulticastDNS selector.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
      ValueName = 'EnableMulticast'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows default applies when the LLMNR policy value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.tailored-experiences-policy'
      Name = 'Tailored experiences policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Disable tailored experiences based on diagnostic data for the current user.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent'
      ValueName = 'DisableTailoredExperiencesWithDiagnosticData'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows tailored-experience behavior applies when no user policy override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.activity-history-feed-policy'
      Name = 'Activity history feed policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Disable the activity feed through the machine policy value used by the legacy activity-history selector.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
      ValueName = 'EnableActivityFeed'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows activity-history behavior applies when no machine policy override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.activity-history-publish-policy'
      Name = 'Activity history publishing policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Disable publishing user activities through machine policy.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
      ValueName = 'PublishUserActivities'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows activity publishing behavior applies when no machine policy override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.activity-history-upload-policy'
      Name = 'Activity history upload policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Disable uploading user activities through machine policy.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
      ValueName = 'UploadUserActivities'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows activity-upload behavior applies when no machine policy override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.location-service-policy'
      Name = 'Location service policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Disable location services through machine policy.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-sensors'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
      ValueName = 'DisableLocation'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows location behavior applies when no machine policy override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.location-scripting-policy'
      Name = 'Location scripting policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Disable location scripting through machine policy.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-sensors'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
      ValueName = 'DisableLocationScripting'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows location-scripting behavior applies when no machine policy override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.advertising-id-policy'
      Name = 'Advertising ID policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Disable the advertising ID through machine policy.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
      ValueName = 'DisabledByGroupPolicy'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows advertising-ID behavior applies when no machine policy override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.website-language-list-policy'
      Name = 'Website language-list access policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Opt out of sharing the current user''s language list with websites.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/privacy/windows-10-and-privacy-compliance'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\International\User Profile'
      ValueName = 'HttpAcceptLanguageOptOut'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'The language list is available to websites unless the user opts out' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.maintenance-wake-policy'
      Name = 'Automatic maintenance wake policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System'
      Description = 'Disable the Windows Update automatic-maintenance power-management policy value.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
      ValueName = 'AUPowerManagement'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows automatic-maintenance power behavior applies when no policy override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.maintenance-wake-timer'
      Name = 'Automatic maintenance wake timer'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System'
      Description = 'Disable the Windows automatic-maintenance wake timer.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/taskschd/task-maintenence'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance'
      ValueName = 'WakeUp'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows automatic-maintenance wake behavior applies when no explicit value is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.shared-experiences-policy'
      Name = 'Shared experiences policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System'
      Description = 'Set whether the current user allows shared experiences across devices.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/privacy/windows-10-and-privacy-compliance'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP'
      ValueName = 'RomeSdkChannelUserAuthzPolicy'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1 }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows shared-experiences behavior applies when no user override is present' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.long-paths-policy'
      Name = 'Long paths policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System'
      Description = 'Set whether Win32 long-path support is enabled for applications that opt in.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
      ValueName = 'LongPathsEnabled'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0 }
      BaselineState = 'Disabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Applications use the traditional path-length limit unless Windows and the application enable long paths' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.action-center-policy'
      Name = 'Notification Center visibility policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Hide Notification Center through DisableNotificationCenter=1, or remove that policy override with Enabled. Notifications can still appear as banners; windows.toast-notifications-policy controls the separate legacy banner preference. Supported policy editions may require a restart for the visible change. This does not implement both writes from DisableActionCenter.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-taskbar#disablenotificationcenter'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'
      ValueName = 'DisableNotificationCenter'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Action Center notifications remain enabled when no policy value exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.toast-notifications-policy'
      Name = 'Notification banners (legacy preference)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Write ToastEnabled=0 to suppress notification banners, or remove that user preference with Enabled. Separate from Notification Center visibility. This is one part of legacy DisableActionCenter; the Microsoft reference describes notification settings, not the exact ToastEnabled mapping. Confirm current Windows 11 banner behavior before relying on it.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/notifications-and-do-not-disturb-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications'
      ValueName = 'ToastEnabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Toast notifications use the Windows default when no user value exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.lock-screen-blur'
      Name = 'Lock screen background blur'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Disable the acrylic blur on the sign-in screen.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-logon'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
      ValueName = 'DisableAcrylicBackgroundOnLogon'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows controls the sign-in background when this policy is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.sticky-keys-prompts'
      Name = 'Sticky Keys prompts'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Disable the Sticky Keys accessibility prompt for the current user.'
      DocumentationUri = 'https://support.microsoft.com/en-us/accessibility/windows/make-your-mouse-keyboard-and-other-input-devices-easier-to-use'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\Accessibility\StickyKeys'
      ValueName = 'Flags'
      ValueType = 'String'
      States = @{ Disabled = '506'; Enabled = '510' }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = '510'; EffectiveDefault = 'Windows accessibility default flags enable the Sticky Keys prompt' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.toggle-keys-prompts'
      Name = 'Toggle Keys prompts'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Disable the Toggle Keys accessibility prompt for the current user.'
      DocumentationUri = 'https://support.microsoft.com/en-us/accessibility/windows/make-your-mouse-keyboard-and-other-input-devices-easier-to-use'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\Accessibility\ToggleKeys'
      ValueName = 'Flags'
      ValueType = 'String'
      States = @{ Disabled = '58'; Enabled = '62' }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = '62'; EffectiveDefault = 'Windows accessibility default flags enable the Toggle Keys prompt' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.filter-keys-prompts'
      Name = 'Filter Keys prompts'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Disable the Filter Keys accessibility prompt for the current user.'
      DocumentationUri = 'https://support.microsoft.com/en-us/accessibility/windows/make-your-mouse-keyboard-and-other-input-devices-easier-to-use'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\Accessibility\Keyboard Response'
      ValueName = 'Flags'
      ValueType = 'String'
      States = @{ Disabled = '122'; Enabled = '126' }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = '126'; EffectiveDefault = 'Windows accessibility default flags enable the Filter Keys prompt' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.file-operation-details'
      Name = 'File operation details'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Show detailed progress information for File Explorer operations.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager'
      ValueName = 'EnthusiastMode'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = $null }
      BaselineState = 'Disabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Compact file operation details are used unless detailed mode is enabled' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.taskbar-search-visibility'
      Name = 'Taskbar search visibility'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Hide taskbar search for the current user.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
      ValueName = 'SearchboxTaskbarMode'
      ValueType = 'DWord'
      States = @{ Hidden = 0; Icon = 1; Box = 2 }
      BaselineState = 'Box'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 2; EffectiveDefault = 'Search box is shown when Windows uses the full taskbar search preference' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-view-button'
      Name = 'Task View taskbar button'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control visibility of the Task View taskbar button.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'ShowTaskViewButton'
      ValueType = 'DWord'
      States = @{ Hidden = 0; Visible = $null }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Task View button follows the Windows shell default when no override exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.taskbar-combine-primary'
      Name = 'Primary taskbar button combining'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Choose when taskbar buttons combine on the primary display.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'TaskbarGlomLevel'
      ValueType = 'DWord'
      States = @{ WhenFull = 1; Never = 2; Always = $null }
      BaselineState = 'Always'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Taskbar buttons combine using the Windows default when no override exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.taskbar-combine-secondary'
      Name = 'Secondary taskbar button combining'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Choose when taskbar buttons combine on secondary displays.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'MMTaskbarGlomLevel'
      ValueType = 'DWord'
      States = @{ WhenFull = 1; Never = 2; Always = $null }
      BaselineState = 'Always'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Secondary taskbar buttons combine using the Windows default when no override exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.taskbar-people-icon'
      Name = 'Taskbar People icon'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control visibility of the legacy People taskbar icon.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
      ValueName = 'PeopleBand'
      ValueType = 'DWord'
      States = @{ Hidden = 0; Visible = $null }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'The People icon is not configured by RIDE when its value is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.tray-icon-promotion'
      Name = 'Notification area icon promotion'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Show all notification area icons without automatic overflow promotion.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
      ValueName = 'NoAutoTrayNotify'
      ValueType = 'DWord'
      States = @{ ShowAll = 1; Automatic = $null }
      BaselineState = 'Automatic'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows manages notification area icon overflow when no policy value exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.store-app-suggestion'
      Name = 'Microsoft Store open-with suggestion'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Disable searching the Microsoft Store for an app to open an unknown file type.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-icm'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
      ValueName = 'NoUseStoreOpenWith'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows offers Store search when this policy is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.new-app-alert'
      Name = 'New app open-with alert'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Disable the prompt asking how to open a file when no default app is set.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
      ValueName = 'NoNewAppAlert'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows shows the open-with prompt when this policy is absent' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.startup-sound'
      Name = 'Windows startup sound'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control playback of the Windows startup sound.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/personalize-your-windows-experience-with-themes'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation'
      ValueName = 'DisableStartupSound'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = 0 }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Startup sound behavior follows the Windows default when no explicit value exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.taskbar-widgets'
      Name = 'Taskbar Widgets button'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control visibility of the Widgets button on the taskbar.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/stay-up-to-date-with-widgets-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'TaskbarDa'
      ValueType = 'DWord'
      States = @{ Hidden = 0; Visible = $null }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Widgets button follows the Windows shell default when no per-user value exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.taskbar-chat'
      Name = 'Taskbar Chat button'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control visibility of the Chat button on the taskbar.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'TaskbarMn'
      ValueType = 'DWord'
      States = @{ Hidden = 0; Visible = $null }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Chat button follows the Windows shell default when no per-user value exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.taskbar-clock-seconds'
      Name = 'Taskbar clock seconds'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Show seconds in the current-user system tray clock. The registry mapping is retained from the legacy selector; Microsoft documents the user-visible setting.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/set-time-date-and-time-zone-settings-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'ShowSecondsInSystemClock'
      ValueType = 'DWord'
      States = @{ Shown = 1; Hidden = $null }
      BaselineState = 'Hidden'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'The system tray clock normally hides seconds unless the user enables them' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.recycle-bin-delete-confirmation'
      Name = 'Recycle Bin delete confirmation'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Show a confirmation dialog when deleting items to the Recycle Bin. The registry mapping is retained from the legacy selector; Microsoft documents the user-visible setting.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/backup-recovery/windows-backup-settings-catalog'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
      ValueName = 'ConfirmFileDelete'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = $null }
      BaselineState = 'Disabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Delete confirmation is off unless the user enables the dialog' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.edge-tabs-alt-tab'
      Name = 'Microsoft Edge tabs in Alt+Tab'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Exclude Microsoft Edge tabs from the Alt+Tab switcher.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/how-to-multitask-in-windows-b4fa0333-98f8-ef43-e25c-06d4fb1d6960'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'MultiTaskingAltTabFilter'
      ValueType = 'DWord'
      States = @{ Excluded = 3; RecentTabs = 1; ThreeRecentTabs = 2; AllRecentTabs = 0 }
      BaselineState = 'RecentTabs'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 1; EffectiveDefault = 'Alt+Tab includes open windows and recent Edge tabs by default' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.desktop-icons-visibility'
      Name = 'Desktop icons visibility'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show or hide all icons on the current user desktop. The registry mapping is retained from the legacy selectors; Microsoft documents the user-visible setting.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'HideIcons'
      ValueType = 'DWord'
      States = @{ Visible = 0; Hidden = 1 }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Desktop icons are shown unless the user hides them' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.hidden-files-visibility'
      Name = 'Hidden files visibility'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show hidden files in File Explorer.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/deployment/install-upgrade/find-lost-files-after-upgrading-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'Hidden'
      ValueType = 'DWord'
      States = @{ Visible = 1; Hidden = 2 }
      BaselineState = 'Hidden'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 2; EffectiveDefault = 'Hidden files are not shown by default' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.navigation-pane-auto-expand'
      Name = 'Navigation pane auto-expand'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Expand the File Explorer navigation pane to the current folder.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'NavPaneExpandToCurrentFolder'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = $null }
      BaselineState = 'Disabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Navigation pane does not auto-expand unless enabled by the user' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.sync-provider-notifications'
      Name = 'Sync provider notifications'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Hide sync provider notifications in File Explorer.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'ShowSyncProviderNotifications'
      ValueType = 'DWord'
      States = @{ Hidden = 0; Visible = $null }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Sync provider notifications follow the Windows shell default when no override exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.explorer-recent-shortcuts'
      Name = 'Recent file shortcuts in File Explorer'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Hide recent file shortcuts in File Explorer Home.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/backup-recovery/windows-backup-settings-catalog'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
      ValueName = 'ShowRecent'
      ValueType = 'DWord'
      States = @{ Hidden = 0; Visible = $null }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Recent file shortcuts follow the Windows Home default when no user override exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.explorer-frequent-shortcuts'
      Name = 'Frequent folder shortcuts in File Explorer'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Hide frequent folder shortcuts in File Explorer Home.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/backup-recovery/windows-backup-settings-catalog'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
      ValueName = 'ShowFrequent'
      ValueType = 'DWord'
      States = @{ Hidden = 0; Visible = $null }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Frequent folder shortcuts follow the Windows Home default when no user override exists' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.explorer-start-location'
      Name = 'File Explorer start location'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Open File Explorer to This PC instead of Home.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'LaunchTo'
      ValueType = 'DWord'
      States = @{ ThisPC = 1; Home = 2 }
      BaselineState = 'Home'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 2; EffectiveDefault = 'File Explorer opens to Home by default' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.thumbnail-cache-creation'
      Name = 'Thumbnail cache creation'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Disable creation of thumbnail cache files for the current user.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'DisableThumbnailCache'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Thumbnail cache creation is enabled unless explicitly disabled' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.network-thumbnail-database'
      Name = 'Network folder thumbnail database'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Disable Thumbs.db creation on network folders.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      ValueName = 'DisableThumbsDBOnNetworkFolders'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Thumbs.db creation on network folders is enabled unless explicitly disabled' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.music-folder-this-pc'
      Name = 'Music folder in This PC'
      Kind = 'RegistryKeySet'
      Category = 'Windows settings / Explorer'
      Description = 'Hide or show the Music entries in This PC by managing their Shell namespace registration keys. Hidden leaves the Music folder and its contents in place.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryKeySet'
      RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}'
      )
      States = @{ Hidden = 'Absent'; Visible = 'Present' }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Windows and its registered Shell namespace extensions determine whether the Music entries appear in This PC' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.videos-folder-this-pc'
      Name = 'Videos folder in This PC'
      Kind = 'RegistryKeySet'
      Category = 'Windows settings / Explorer'
      Description = 'Hide or show the Videos entries in This PC by managing their Shell namespace registration keys. Hidden leaves the Videos folder and its contents in place.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryKeySet'
      RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}'
      )
      States = @{ Hidden = 'Absent'; Visible = 'Present' }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Windows and its registered Shell namespace extensions determine whether the Videos entries appear in This PC' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.3d-objects-folder-this-pc'
      Name = '3D Objects folder in This PC'
      Kind = 'RegistryKeySet'
      Category = 'Windows settings / Explorer'
      Description = 'Hide or show the 3D Objects entry in This PC by managing its Shell namespace registration key. Hidden leaves the 3D Objects folder and its contents in place.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryKeySet'
      RegistryPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}')
      States = @{ Hidden = 'Absent'; Visible = 'Present' }
      BaselineState = 'Visible'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Windows and its registered Shell namespace extensions determine whether the 3D Objects entry appears in This PC' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'package.7zip'
      Name = '7-Zip'
      Kind = 'Package'
      Category = 'Software / Utilities'
      Description = 'Download, install, or remove the current 64-bit 7-Zip release.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }
        'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }
      }
      PackageId = '7zip'
      InstallerType = 'Exe'
      DisplayNamePattern = '^7-Zip'
      DownloadUri = 'https://api.github.com/repos/ip7z/7zip/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      AssetPattern = '^7z\d+-x64\.exe$'
      Architecture = 'x64'
      ProductUri = 'https://www.7-zip.org/'
      License = 'LGPL-2.1-or-later; BSD components and unRAR restriction'
      LicenseUri = 'https://www.7-zip.org/license.txt'
      InstallerArguments = '/S'
      UninstallerArguments = '/S'
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.notepadpp'
      Name = 'Notepad++'
      Kind = 'Package'
      Category = 'Software / Utilities'
      Description = 'Download, install, or remove the current 64-bit Notepad++ release.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }
        'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }
      }
      PackageId = 'notepadpp'
      InstallerType = 'Exe'
      DisplayNamePattern = '^Notepad\+\+'
      DownloadUri = 'https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      AssetPattern = '^npp\..+\.Installer\.x64\.exe$'
      Architecture = 'x64'
      ProductUri = 'https://notepad-plus-plus.org/'
      License = 'GPL-3.0 with upstream clarifications and exceptions'
      LicenseUri = 'https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/LICENSE'
      InstallerArguments = '/S'
      UninstallerArguments = '/S'
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.git-for-windows'
      Name = 'Git for Windows'
      Kind = 'Package'
      Category = 'Software / Development Tools'
      Description = 'Download, install, or remove the current 64-bit Git for Windows release.'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }
      }
      PackageId = 'git-for-windows'
      PublisherChecksumSource = 'ReleaseNotes'
      InstallerType = 'Exe'
      DisplayNamePattern = '^Git(?:$| version\b)'
      DownloadUri = 'https://api.github.com/repos/git-for-windows/git/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      AssetPattern = '^Git-\d+\.\d+\.\d+(?:\.\d+)?-64-bit\.exe$'
      Architecture = 'x64'
      ProductUri = 'https://gitforwindows.org/'
      License = 'GPL-2.0; bundled components have separate licenses'
      LicenseUri = 'https://github.com/git-for-windows/git/blob/main/COPYING'
      InstallerArguments = '/VERYSILENT /NORESTART /NOCANCEL /SP-'
      UninstallerArguments = '/VERYSILENT /NORESTART /NOCANCEL /SP-'
      Rollback = 'Compensating'
    }
    @{
      Id = 'artifact.sysmon-swift-config'
      Name = 'SwiftOnSecurity Sysmon configuration'
      Kind = 'Artifact'
      Category = 'Software / Security'
      Description = 'Download the latest SwiftOnSecurity Sysmon XML configuration as a separately versioned file. It is never applied automatically.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Download')
      Handler = 'Artifact'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'DownloadOnly'; EffectiveDefault = 'A downloaded configuration file does not change Sysmon or Windows state' }
        'Windows Server 2025' = @{ DefaultValue = 'DownloadOnly'; EffectiveDefault = 'A downloaded configuration file does not change Sysmon or Windows state' }
      }
      ArtifactId = 'sysmon-swift-config'
      DownloadUri = 'https://api.github.com/repos/SwiftOnSecurity/sysmon-config/commits?path=sysmonconfig-export.xml&per_page=1'
      DownloadProvider = 'GitHubFileCommitApi'
      Repository = 'SwiftOnSecurity/sysmon-config'
      AssetPath = 'sysmonconfig-export.xml'
      Architecture = 'neutral'
      ProductUri = 'https://github.com/SwiftOnSecurity/sysmon-config'
      License = 'CC-BY-4.0 (declared in the XML header)'
      LicenseUri = 'https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml'
      Rollback = 'None'
    }
    @{
      Id = 'package.sysmon64'
      Name = 'Sysmon'
      Kind = 'Package'
      Category = 'Software / Security'
      Description = 'Download and install the latest Microsoft Sysmon archive with its default configuration, or remove its service and driver. A community XML configuration is never applied implicitly.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Standalone Sysmon is not installed in the default Windows image' }
        'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Sysmon is not installed in the default Windows image' }
      }
      PackageId = 'sysmon64'
      InstallerType = 'SysmonZip'
      DisplayNamePattern = '^Sysmon'
      DownloadUri = 'https://download.sysinternals.com/files/Sysmon.zip'
      VersionUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon'
      DownloadProvider = 'SysinternalsSysmonPage'
      AssetName = 'Sysmon.zip'
      AssetPattern = '^Sysmon\.zip$'
      Architecture = 'x64'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = '-accepteula -i'
      UninstallerArguments = '-u force'
      Rollback = 'Compensating'
    }
    @{
      Id = 'windows.admin-share-server'
      Name = 'Administrative shares for Windows Server'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Prevent Windows Server from automatically creating administrative shares, or use the Windows default. Restart the Server service for changes to take effect.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/remove-administrative-shares'
      SupportedTargets = @('Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
      ValueName = 'AutoShareServer'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows Server 2025' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows Server creates default administrative shares unless this value is set to 0' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.admin-share-workstation'
      Name = 'Administrative shares for Windows workstation'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Set the legacy AutoShareWks value to control workstation administrative shares. Microsoft documents the analogous AutoShareServer setting, not this Workstation registry value. Restart the Server service for changes to take effect.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/remove-administrative-shares'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
      ValueName = 'AutoShareWks'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows workstation creates default administrative shares unless this value is set to 0' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.account-protection-warning'
      Name = 'Windows Security account protection warning'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Hide or restore the current user''s account protection warning in the Windows Security app.'
      DocumentationUri = 'https://support.microsoft.com/en-gb/windows/security/windows-security/account-protection-in-the-windows-security-app'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\Microsoft\Windows Security Health\State'
      ValueName = 'AccountProtection_MicrosoftAccount_Disconnected'
      ValueType = 'DWord'
      States = @{ Hidden = 1; Shown = $null }
      BaselineState = 'Shown'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Windows Security displays current account protection information when no override is set' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.dotnet-strong-crypto-64bit'
      Name = '.NET strong cryptography for 64-bit applications'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Configure SchUseStrongCrypto for 64-bit .NET Framework applications. Framework 4.6 and later use strong cryptography by default.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
      ValueName = 'SchUseStrongCrypto'
      ValueType = 'DWord'
      States = @{ Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'The registry value is absent by default; .NET Framework 4.6+ defaults to strong cryptography' }
        'Windows Server 2025' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'The registry value is absent by default; .NET Framework 4.6+ defaults to strong cryptography' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.dotnet-strong-crypto-32bit'
      Name = '.NET strong cryptography for 32-bit applications'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Configure SchUseStrongCrypto for 32-bit .NET Framework applications. Framework 4.6 and later use strong cryptography by default.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
      ValueName = 'SchUseStrongCrypto'
      ValueType = 'DWord'
      States = @{ Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'The registry value is absent by default; .NET Framework 4.6+ defaults to strong cryptography' }
        'Windows Server 2025' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'The registry value is absent by default; .NET Framework 4.6+ defaults to strong cryptography' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.f8-boot-menu-policy'
      Name = 'F8 boot menu policy'
      Kind = 'BootConfiguration'
      Category = 'Windows settings / Security'
      Description = 'Choose Standard or Legacy boot menu behavior. Legacy enables the F8 advanced boot options menu; changes take effect after restart.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'BootConfiguration'
      BcdElement = 'bootmenupolicy'
      States = @{ Standard = $null; Legacy = 'Legacy' }
      BaselineState = 'Standard'
      RestartRequired = $true
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = '<not explicitly set>'; EffectiveDefault = 'Standard is the Windows default boot menu policy; this operation changes boot configuration for the next startup.' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.dep-boot-policy'
      Name = 'Data Execution Prevention boot policy'
      Kind = 'BootConfiguration'
      Category = 'Windows settings / Security'
      Description = 'Windows applies the selected DEP policy during startup. Changes take effect after restart.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'BootConfiguration'
      BcdElement = 'nx'
      States = @{ OptIn = $null; OptOut = 'OptOut' }
      BaselineState = 'OptIn'
      RestartRequired = $true
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = '<not explicitly set>'; EffectiveDefault = 'OptIn is the Windows default DEP policy; this operation changes boot configuration for the next startup.' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.ssdp-discovery-service'
      Name = 'SSDP Discovery service'
      Kind = 'WindowsService'
      Category = 'Windows settings / Security'
      Description = 'Set SSDP Discovery to disabled and stopped, or to manual and running.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'WindowsService'
      ServiceName = 'SSDPSRV'
      States = @{
        Disabled = @{ StartupType = 'Disabled'; Status = 'Stopped' }
        Enabled = @{ StartupType = 'Manual'; Status = 'Running' }
      }
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Manual / Stopped'; EffectiveDefault = 'Manual, trigger-start service; normally stopped until a client requests SSDP functionality' }
        'Windows Server 2025' = @{ DefaultValue = 'Manual / Stopped'; EffectiveDefault = 'Manual, trigger-start service; normally stopped until a client requests SSDP functionality' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.upnp-device-host-service'
      Name = 'UPnP Device Host service'
      Kind = 'WindowsService'
      Category = 'Windows settings / Security'
      Description = 'Set UPnP Device Host to disabled and stopped, or to manual and running.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-systemservices'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'WindowsService'
      ServiceName = 'upnphost'
      States = @{
        Disabled = @{ StartupType = 'Disabled'; Status = 'Stopped' }
        Enabled = @{ StartupType = 'Manual'; Status = 'Running' }
      }
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Manual / Stopped'; EffectiveDefault = 'Manual, trigger-start service; normally stopped until a client requests UPnP hosting' }
        'Windows Server 2025' = @{ DefaultValue = 'Manual / Stopped'; EffectiveDefault = 'Manual, trigger-start service; normally stopped until a client requests UPnP hosting' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.winhttp-wpad-policy'
      Name = 'WinHTTP WPAD detection'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Disable WinHTTP WPAD detection using the documented machine registry value; this does not disable the WinHTTP Auto-Proxy service or proxy auto-discovery in every application.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
      ValueName = 'DisableWpad'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = $null }
      BaselineState = 'Enabled'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'WinHTTP WPAD detection is enabled when DisableWpad is absent; other applications may use separate proxy discovery settings' }
        'Windows Server 2025' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'WinHTTP WPAD detection is enabled when DisableWpad is absent; other applications may use separate proxy discovery settings' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.bitlocker-encryption-method'
      Name = 'BitLocker encryption method policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Set the legacy BitLocker EncryptionMethod policy value to AES-CBC 256-bit for future drive encryption; this does not convert drives that are already encrypted.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-bitlocker'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
      ValueName = 'EncryptionMethod'
      ValueType = 'DWord'
      States = @{ AesCbc128 = 3; AesCbc256 = 4; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'With no policy configured, new BitLocker encryption defaults to XTS-AES 128-bit; the legacy selector requests AES-CBC 256-bit for future encryption.' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.current-network-category'
      Name = 'Current network category'
      Kind = 'NetworkProfile'
      Category = 'Windows settings / Network'
      Description = 'Set every reported non-domain connection profile to Private or Public and restore each profile to its captured category.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netconnection/set-netconnectionprofile?view=windowsserver2025-ps'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'NetworkProfile'
      States = @{ Private = 'Private'; Public = 'Public' }
      BaselineState = 'Public'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Assigned per connection'; EffectiveDefault = 'Windows classifies each connection separately; DomainAuthenticated is assigned automatically and this operation leaves those profiles unchanged.' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.remote-assistance-policy'
      Name = 'Remote Assistance policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Allow or disallow users from requesting Remote Assistance by setting the documented fAllowToGetHelp behavior value; Quick Assist is managed separately.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-remoteassistance-exe-fallowtogethelp'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
      ValueName = 'fAllowToGetHelp'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Remote Assistance is disallowed when fAllowToGetHelp is false; Quick Assist is a separate application.' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.microsoft-product-updates'
      Name = 'Microsoft product updates'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Windows Update'
      Description = 'Allow Windows Update to scan for updates to other Microsoft products by setting the documented device preference AllowMUUpdateService.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
      ValueName = 'AllowMUUpdateService'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'Other Microsoft product updates are disabled until Microsoft Update is enabled.' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'package.git-lfs'
      Name = 'Git LFS (standalone installer)'
      Kind = 'Package'
      Category = 'Software / Development Tools'
      Description = 'Install the standalone Git LFS package after machine-wide Git for Windows. Remove Git LFS before Git. The bundled Git component is a separate installation.'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'git-lfs'
      PrerequisitePackageId = 'package.git-for-windows'
      PrerequisiteProgramFilesExecutable = 'Git\cmd\git.exe'
      InstallerType = 'Exe'
      DisplayNamePattern = '^Git LFS(?:\s|$)'
      DownloadUri = 'https://api.github.com/repos/git-lfs/git-lfs/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      AssetPattern = '^git-lfs-windows-v\d+(?:\.\d+)+\.exe$'
      Architecture = 'x64'
      ProductUri = 'https://git-lfs.com/'
      License = 'MIT; bundled components have separate licenses'
      LicenseUri = 'https://github.com/git-lfs/git-lfs/blob/main/LICENSE.md'
      InstallerArguments = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
      UninstallerArguments = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.joplin'
      Name = 'Joplin'
      Kind = 'Package'
      Category = 'Software / Productivity'
      Description = 'Install or remove the current-user Joplin desktop application; notebooks are preserved by the publisher uninstaller.'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'joplin'
      InstallerType = 'Exe'
      DisplayNamePattern = '^Joplin(?:\s|$)'
      DownloadUri = 'https://api.github.com/repos/laurent22/joplin/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      AssetPattern = '^Joplin-Setup-\d+(?:\.\d+)+\.exe$'
      Architecture = 'x64'
      ProductUri = 'https://joplinapp.org/'
      License = 'AGPL-3.0-or-later; component and asset exceptions'
      LicenseUri = 'https://github.com/laurent22/joplin/blob/dev/LICENSE'
      InstallerArguments = '/S /currentuser'
      UninstallerArguments = '/S'
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.sharex'
      Name = 'ShareX'
      Kind = 'Package'
      Category = 'Software / Productivity'
      Description = 'Install or remove the current x64 ShareX desktop application.'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'sharex'
      InstallerType = 'Exe'
      DisplayNamePattern = '^ShareX(?:\s|$)'
      DownloadUri = 'https://api.github.com/repos/ShareX/ShareX/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      AssetPattern = '^ShareX-\d+(?:\.\d+)+-setup-x64\.exe$'
      Architecture = 'x64'
      ProductUri = 'https://getsharex.com/'
      License = 'GPL-3.0 (see upstream terms and component notices)'
      LicenseUri = 'https://github.com/ShareX/ShareX/blob/master/LICENSE.txt'
      InstallerArguments = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /ALLUSERS'
      UninstallerArguments = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
      Rollback = 'Compensating'
      DefaultVariant = 'installed'
      Variants = @{
        installed = @{}
        portable = @{ InstallerType = 'Portable'; Scope = 'Machine'; RequiresAdmin = $true; PortableFormat = 'Zip'; RequiredFiles = @('ShareX.exe'); AssetPattern = '^ShareX-[0-9.]+-portable-x64\.zip$'; Rollback = 'Exact'; MigrationBatch = 'ApplicationsBatch2'; SupportedTargets = @('Windows 11', 'Windows Server 2025'); PendingAcceptance = $false; TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } } }
      }
      RequiresDesktopExperience = $true
    }
    @{
      Id = 'package.windirstat'
      Name = 'WinDirStat'
      Kind = 'Package'
      Category = 'Software / Utilities'
      Description = 'Install or remove the current x64 WinDirStat MSI package.'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'windirstat'
      InstallerType = 'Msi'
      DisplayNamePattern = '^WinDirStat(?:\s|$)'
      DownloadUri = 'https://api.github.com/repos/windirstat/windirstat/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      TagPrefix = 'release/'
      AssetPattern = '^WinDirStat-x64\.msi$'
      Architecture = 'x64'
      ProductUri = 'https://windirstat.net/'
      License = 'GPL-3.0-or-later; separate component and logo licenses'
      LicenseUri = 'https://github.com/windirstat/windirstat#copyright--licenses'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.powershell'
      Name = 'PowerShell 7'
      Kind = 'Package'
      Category = 'Software / Development Tools'
      Description = 'Install or remove the latest stable x64 PowerShell MSI; Windows PowerShell remains separate.'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'PowerShell 7 is not installed in the default Windows image' } }
      PackageId = 'powershell'
      InstallerType = 'Msi'
      DisplayNamePattern = '^PowerShell 7(?:-x64|(?:\.\d+)*)(?:\s|$)'
      DownloadUri = 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      AssetPattern = '^PowerShell-\d+(?:\.\d+)+-win-x64\.msi$'
      Architecture = 'x64'
      ProductUri = 'https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows'
      License = 'MIT; bundled components have separate licenses'
      LicenseUri = 'https://github.com/PowerShell/PowerShell/blob/master/LICENSE.txt'
      InstallerArguments = '/qn /norestart ADD_PATH=1'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'windows.lid-close-action-ac'
      Name = 'Lid close action on AC power'
      Kind = 'PowerSetting'
      Category = 'Windows settings / Power'
      Description = 'Choose whether closing the lid sleeps or does nothing while the device is connected to AC power.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'PowerSetting'
      PowerSubgroupGuid = '4f971e89-eebd-4455-a8de-9e59040e7347'
      PowerSettingGuid = '5ca83367-6e45-459f-a27b-476b1d01c936'
      PowerIndex = 'AC'
      States = @{ DoNothing = 0; Sleep = 1 }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Platform-defined'; EffectiveDefault = 'The active power scheme and device configuration determine the current lid-close action' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.lid-close-action-dc'
      Name = 'Lid close action on battery'
      Kind = 'PowerSetting'
      Category = 'Windows settings / Power'
      Description = 'Choose whether closing the lid sleeps or does nothing while the device is running on battery power.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'PowerSetting'
      PowerSubgroupGuid = '4f971e89-eebd-4455-a8de-9e59040e7347'
      PowerSettingGuid = '5ca83367-6e45-459f-a27b-476b1d01c936'
      PowerIndex = 'DC'
      States = @{ DoNothing = 0; Sleep = 1 }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Platform-defined'; EffectiveDefault = 'The active power scheme and device configuration determine the current lid-close action' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-compatibility-appraiser'
      Name = 'Application compatibility appraisal'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Collects application compatibility information used in upgrade readiness. Disabling its schedule can affect compatibility assessment; this does not disable all diagnostic data. The reference documents the task API; the legacy identity is not a current feature guarantee.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      TaskPath = '\Microsoft\Windows\Application Experience\'
      TaskName = 'Microsoft Compatibility Appraiser'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-program-data-updater'
      Name = 'Application compatibility program-data update'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Controls the existing ProgramDataUpdater task schedule. Its current payload is build-dependent; the cmdlet reference documents enablement, not a verified complete privacy outcome. The reference documents the task API; the legacy identity is not a current feature guarantee.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      TaskPath = '\Microsoft\Windows\Application Experience\'
      TaskName = 'ProgramDataUpdater'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-autochk-proxy'
      Name = 'Autochk diagnostic proxy'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Controls the existing Autochk Proxy task schedule. This does not disable disk checking or prove suppression of every disk diagnostic. The reference documents the task API; the legacy identity is not a current feature guarantee.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      TaskPath = '\Microsoft\Windows\Autochk\'
      TaskName = 'Proxy'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-ceip-consolidator'
      Name = 'Customer Experience Improvement Program consolidation'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Controls the existing CEIP Consolidator task schedule. Missing legacy tasks are unavailable; disabling this task does not disable Windows diagnostic-data policy. The reference documents the task API; the legacy identity is not a current feature guarantee.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program\'
      TaskName = 'Consolidator'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-usb-ceip'
      Name = 'USB customer-experience diagnostic task'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Controls the existing UsbCeip task schedule. USB device operation and other diagnostic-data controls remain separate. The reference documents the task API; the legacy identity is not a current feature guarantee.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program\'
      TaskName = 'UsbCeip'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-disk-diagnostic-collector'
      Name = 'Disk diagnostic data collection task'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Controls the existing disk diagnostic data collector schedule. This does not disable disk checking, repair or the diagnostic service. The reference documents the task API; the legacy identity is not a current feature guarantee.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      TaskPath = '\Microsoft\Windows\DiskDiagnostic\'
      TaskName = 'Microsoft-Windows-DiskDiagnosticDataCollector'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-feedback-client'
      Name = 'Feedback request client'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Controls the schedule of the existing Feedback Siuf DmClient task. Availability and payload depend on the Windows build. Feedback notification policy and frequency remain separate; the API reference establishes task enablement, not complete suppression of feedback requests.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableFeedback', 'EnableFeedback')
      TaskPath = '\Microsoft\Windows\Feedback\Siuf\'
      TaskName = 'DmClient'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-feedback-scenario'
      Name = 'Feedback scenario-download client'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Controls the schedule of the existing Feedback Siuf DmClientOnScenarioDownload task. Its exact downloaded-scenario behavior remains build-dependent and unverified. This is separate from DmClient, notification policy and feedback frequency; the reference documents only the task API.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableFeedback', 'EnableFeedback')
      TaskPath = '\Microsoft\Windows\Feedback\Siuf\'
      TaskName = 'DmClientOnScenarioDownload'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-error-report-queue'
      Name = 'Windows Error Reporting queue task'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Controls only the existing QueueReporting task schedule. Windows Error Reporting policy, service and application error-reporting behavior remain separate. The reference documents the task API.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableErrorReporting', 'EnableErrorReporting')
      TaskPath = '\Microsoft\Windows\Windows Error Reporting\'
      TaskName = 'QueueReporting'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.task-drive-optimization'
      Name = 'Scheduled drive optimization'
      Kind = 'ScheduledTask'
      Category = 'Windows settings / Scheduled tasks'
      Description = 'Controls the existing ScheduledDefrag task schedule, including Windows drive optimization appropriate to the drive type. Disabling the schedule does not run optimization or change manual optimization. The reference documents the task API.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableDefragmentation', 'EnableDefragmentation')
      TaskPath = '\Microsoft\Windows\Defrag\'
      TaskName = 'ScheduledDefrag'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'application.office-task-click-to-run-monitor'
      Name = 'Office Click-to-Run service monitoring'
      Kind = 'ScheduledTask'
      Category = 'Application settings / Office'
      Description = 'Controls the existing Office ClickToRun Service Monitor schedule. This is Office installation/service maintenance, so disabling it can affect maintenance rather than providing a general privacy outcome. It is unavailable without the matching task; the reference documents task enablement.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      TaskPath = '\Microsoft\Office\'
      TaskName = 'Office ClickToRun Service Monitor'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'application.office-task-telemetry-fallback-2016'
      Name = 'Office 2016 telemetry fallback task'
      Kind = 'ScheduledTask'
      Category = 'Application settings / Office'
      Description = 'Controls the existing OfficeTelemetryAgentFallBack2016 task schedule. This identifies the fallback Office 2016 telemetry-agent task, not the logon task. Its current payload and installed-version applicability require acceptance; disabling it does not establish complete Office diagnostic-data suppression. The reference documents the task API.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      TaskPath = '\Microsoft\Office\'
      TaskName = 'OfficeTelemetryAgentFallBack2016'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'application.office-task-telemetry-logon-2016'
      Name = 'Office 2016 telemetry logon task'
      Kind = 'ScheduledTask'
      Category = 'Application settings / Office'
      Description = 'Controls the existing OfficeTelemetryAgentLogOn2016 task schedule. This identifies the Office 2016 telemetry-agent logon task, separately from its fallback task. Missing tasks are unavailable; current payload and Office diagnostic-policy interaction require acceptance. The reference documents the task API.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ScheduledTask'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      TaskPath = '\Microsoft\Office\'
      TaskName = 'OfficeTelemetryAgentLogOn2016'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.application-impact-telemetry'
      Name = 'Application impact telemetry policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Policy'
      Description = 'Controls application-impact telemetry for Windows components used by applications. Disabled writes AITEnable=0; WindowsDefault removes the override. CEIP policy can suppress this independently; restart or new application activity may be required.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-appcompat#appcompatturnoffapplicationimpacttelemetry'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
      ValueName = 'AITEnable'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.application-inventory-policy'
      Name = 'Application compatibility inventory policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Policy'
      Description = 'Controls the application compatibility inventory collector for installed applications, files, devices and drivers. Disabled writes DisableInventory=1; WindowsDefault removes the override. CEIP and diagnostic-data policy can independently affect collection.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-appcompat#appcompatturnoffprograminventory'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
      ValueName = 'DisableInventory'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.start-most-used-policy'
      Name = 'Start menu most-used application list policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Policy'
      Description = 'Hides the frequently used application list in Start with Hidden=1; Allowed=0 explicitly permits it. WindowsDefault removes the policy override. Tracking preferences and other policies can still prevent the list from appearing. Restart or shell refresh and current Start-layout acceptance remain separate.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start#hidefrequentlyusedapps'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('HideMostUsedApps', 'ShowMostUsedApps')
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
      ValueName = 'NoStartMenuMFUprogramsList'
      ValueType = 'DWord'
      States = @{ Allowed = 0; Hidden = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.secure-attention-logon'
      Name = 'Ctrl+Alt+Delete requirement before sign-in'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Policy'
      Description = 'Required writes DisableCAD=0, requiring the secure attention sequence before interactive sign-in. NotRequired writes 1. WindowsDefault removes the override; domain policy can take precedence. The policy reference describes sign-in behavior; test the actual sign-in screen separately.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-require-ctrl-alt-del'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      MigrationBatch = '2026-10-10-remaining-settings-1'
      LegacySelectors = @('DisableCtrlAltDelLogin', 'EnableCtrlAltDelLogin')
      RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      ValueName = 'DisableCAD'
      ValueType = 'DWord'
      States = @{ NotRequired = 1; Required = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.adapter-lldp-binding'
      Name = 'Link Layer Discovery Protocol adapter binding'
      Kind = 'AdapterBinding'
      Category = 'Windows settings / Network bindings'
      Description = 'Enables or disables the Microsoft Link Layer Discovery Protocol binding (ms_lldp) on currently visible adapters. This controls the LLDP binding rather than the separate LLTD topology mapper/responder. Capture includes stable adapter GUIDs and coupled flags for restore; new adapters remain untouched. Actual neighbor discovery requires peer acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapterbinding'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'AdapterBinding'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableLLDP', 'EnableLLDP')
      ComponentIds = @('ms_lldp')
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.adapter-lltd-binding'
      Name = 'Link Layer Topology Discovery adapter binding'
      Kind = 'AdapterBinding'
      Category = 'Windows settings / Network bindings'
      Description = 'Enables or disables Link Layer Topology Discovery mapper (ms_lltdio) and responder (ms_rspndr) together on currently visible adapters. They implement one topology-discovery feature. Stable adapter GUIDs and coupled flags are captured for restore; new adapters remain untouched. Missing components and actual topology behavior require acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapterbinding'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'AdapterBinding'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableLLTD', 'EnableLLTD')
      ComponentIds = @('ms_lltdio', 'ms_rspndr')
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.adapter-microsoft-network-client-binding'
      Name = 'Client for Microsoft Networks adapter binding'
      Kind = 'AdapterBinding'
      Category = 'Windows settings / Network bindings'
      Description = 'Enables or disables Client for Microsoft Networks (ms_msclient) on currently visible adapters. This binding supports accessing Microsoft network resources; it is distinct from the server sharing binding and SMB protocol flags. Stable GUIDs and coupled flags are captured for restore. Peer access may be interrupted; new adapters remain untouched.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapterbinding'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'AdapterBinding'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableMSNetClient', 'EnableMSNetClient')
      ComponentIds = @('ms_msclient')
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.adapter-qos-packet-scheduler-binding'
      Name = 'QoS packet scheduler adapter binding'
      Kind = 'AdapterBinding'
      Category = 'Windows settings / Network bindings'
      Description = 'Enables or disables QoS Packet Scheduler (ms_pacer) on currently visible adapters. It controls the scheduler binding, not a promised bandwidth increase or a universal reservation percentage. Stable adapter GUIDs and coupled flags are captured for restore; new adapters remain untouched. Actual traffic behavior requires acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapterbinding'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'AdapterBinding'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableQoS', 'EnableQoS')
      ComponentIds = @('ms_pacer')
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.adapter-ipv4-binding'
      Name = 'IPv4 transport adapter binding'
      Kind = 'AdapterBinding'
      Category = 'Windows settings / Network bindings'
      Description = 'Enables or disables Internet Protocol Version 4 (ms_tcpip) on currently visible adapters. Disabling it can immediately interrupt IPv4 connectivity, including remote management. Stable adapter GUIDs and coupled flags are captured for local restore; new adapters remain untouched. IPv6 and SMB server protocol flags are separate controls.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapterbinding'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'AdapterBinding'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableIPv4', 'EnableIPv4')
      ComponentIds = @('ms_tcpip')
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.adapter-ipv6-binding'
      Name = 'IPv6 transport adapter binding'
      Kind = 'AdapterBinding'
      Category = 'Windows settings / Network bindings'
      Description = 'Enables or disables Internet Protocol Version 6 (ms_tcpip6) on currently visible adapters. Disabling it can interrupt IPv6 connectivity and dependent Windows features; this binding flag does not disable every IPv6 subsystem. Stable adapter GUIDs and coupled flags are captured for local restore; new adapters remain untouched.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapterbinding'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'AdapterBinding'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableIPv6', 'EnableIPv6')
      ComponentIds = @('ms_tcpip6')
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.adapter-file-printer-sharing-binding'
      Name = 'File and Printer Sharing for Microsoft Networks adapter binding'
      Kind = 'AdapterBinding'
      Category = 'Windows settings / Network bindings'
      Description = 'Enables or disables File and Printer Sharing for Microsoft Networks (ms_server) on currently visible adapters. This is the server sharing binding; SMB protocol versions, firewall rules and installed components remain separate. Stable adapter GUIDs and coupled flags are captured for restore; new adapters remain untouched. Real peer sharing requires acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapterbinding'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'AdapterBinding'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableSMBServer', 'EnableSMBServer')
      ComponentIds = @('ms_server')
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.smb1-server-protocol'
      Name = 'SMB 1 server protocol'
      Kind = 'SmbProtocol'
      Category = 'Windows settings / Network'
      Description = 'Controls only the EnableSMB1Protocol server flag when its srv driver service is present. An absent driver is unavailable; no optional feature is installed. Enabling SMB1 can expose an obsolete insecure protocol. SMB2/3, client components, sharing bindings and firewall rules are separate. The legacy EnableSMBServer reverse selector leaves SMB1 unchanged; restore recovers the captured flag.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'SmbProtocol'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableSMB1', 'EnableSMB1', 'DisableSMBServer')
      Preference = 'EnableSMB1Protocol'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.smb2-server-protocol'
      Name = 'SMB 2 and SMB 3 server protocols'
      Kind = 'SmbProtocol'
      Category = 'Windows settings / Network'
      Description = 'Controls the EnableSMB2Protocol server flag, which governs both SMB2 and SMB3. Disabling it can prevent modern SMB clients from reaching shares. SMB1, client components, sharing bindings and firewall rules remain separate. No optional feature is installed; restore recovers the captured flag.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'SmbProtocol'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableSMBServer', 'EnableSMBServer')
      Preference = 'EnableSMB2Protocol'
      States = @{ Disabled = $false; Enabled = $true }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.controlled-folder-access'
      Name = 'Defender Controlled Folder Access mode'
      Kind = 'DefenderPreference'
      Category = 'Windows settings / Security'
      Description = 'Sets Controlled Folder Access to blocking, audit-only or disabled mode through Defender. Requires active compatible Defender protection; managed policy or tamper protection may reject changes. Does not add exclusions or allowed applications. Restore preserves the captured literal mode.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'DefenderPreference'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('EnableCtrldFolderAccess', 'DisableCtrldFolderAccess')
      Preference = 'EnableControlledFolderAccess'
      States = @{ Audit = 2; Disabled = 0; Enabled = 1 }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.active-power-scheme'
      Name = 'Active existing Windows power scheme'
      Kind = 'PowerScheme'
      Category = 'Windows settings / Power'
      Description = 'Selects an existing Balanced or High Performance scheme by stable GUID without parsing localized names. Exact GUID queries inspect schemes even when omitted from the list; device capabilities or policy can still prevent activation. Does not create, duplicate or delete schemes. Ultimate Performance selection and scheme creation remain deferred. Apply and restore verify the active GUID; a failed activation is reported.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'PowerScheme'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('SetPowerSchemeBalanced', 'SetPowerSchemeHighPerf')

      States = @{ Balanced = '381b4222-f694-41f0-9685-ff5bb260df2e'; HighPerformance = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.ncsi-active-probe-policy'
      Name = 'NCSI active connectivity tests policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Policy'
      Description = 'Controls the policy override for NCSI active Internet connectivity tests. Disabled writes NoActiveProbe=1; Enabled writes 0. WindowsDefault removes the policy override. The separate NlaSvc EnableActiveProbing preference and managed policy can affect the result. Disabling probes can disrupt application connectivity detection.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableNCSIProbe', 'EnableNCSIProbe')
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator'
      ValueName = 'NoActiveProbe'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.netbios-over-tcpip'
      Name = 'NetBIOS over TCP/IP adapter configuration'
      Kind = 'NetBios'
      Category = 'Windows settings / Network'
      Description = 'Sets the NetbiosOptions registry preference on existing GUID-named NetBT interface keys: Disabled=2, Enabled=1, Dhcp/default=0. This follows the legacy preference and supports static-IP configuration; the CIM DHCP-mode setter cannot restore every such adapter. Captures literal value, type and absence; new interface keys remain untouched by restore. Adapter restart or reboot and peer-connectivity acceptance remain necessary. The Microsoft method reference explains the modes, not this registry mapping.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/settcpipnetbios-method-in-class-win32-networkadapterconfiguration'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'NetBios'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableNetBIOS', 'EnableNetBIOS')

      States = @{ Dhcp = 0; Disabled = 2; Enabled = 1 }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.remote-desktop-firewall'
      Name = 'Remote Desktop local inbound firewall rules'
      Kind = 'RemoteDesktopFirewall'
      Category = 'Windows settings / Network'
      Description = 'Enables or disables existing local RemoteDesktop-* firewall rules in PersistentStore. Captures each individual flag and never creates missing rules. Does not enable Remote Desktop connections, change authentication or override domain firewall policy. Use with the separate connection permission when composing a Remote Desktop outcome.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RemoteDesktopFirewall'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableRemoteDesktop', 'EnableRemoteDesktop')

      States = @{ Disabled = 'False'; Enabled = 'True' }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.remote-desktop-connections'
      Name = 'Remote Desktop connection permission'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Policy'
      Description = 'Allows or denies incoming Remote Desktop connections. Enabled writes fDenyTSConnections=0; Disabled writes 1. WindowsDefault removes the override. Requires a supported Windows edition and service; firewall rules, NLA and managed policy remain separate. The feature reference explains access prerequisites; no credentials or authentication policy are changed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableRemoteDesktop', 'EnableRemoteDesktop')
      RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
      ValueName = 'fDenyTSConnections'
      ValueType = 'DWord'
      States = @{ Disabled = 1; Enabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'windows.registered-sound-scheme'
      Name = 'Registered Windows sound scheme'
      Kind = 'SoundScheme'
      Category = 'Windows settings / Audio'
      Description = 'Selects the registered .None or .Default sound preset and copies each existing event mapping into .Current. Preserves source presets and unrelated data. Missing preset events map to empty sound strings; existing source customizations are respected. Captures raw selector/event types and presence for restore. The Microsoft reference documents sound configuration behavior, not this registry implementation. Sound UI refresh and actual playback require separate acceptance.'
      DocumentationUri = 'https://support.microsoft.com/en-us/surface/audio/surface-sound-volume-and-audio-accessories'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'SoundScheme'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('SetSoundSchemeNone', 'SetSoundSchemeDefault')

      States = @{ NoneScheme = '.None'; WindowsDefaultScheme = '.Default' }
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'application.edge-startup-boost'
      Name = 'Microsoft Edge startup boost policy'
      Kind = 'RegistryValue'
      Category = 'Application settings / Microsoft Edge'
      Description = 'Controls current Microsoft Edge startup boost, which prestarts browser processes at sign-in and restarts them after the browser closes. Disabled writes 0; WindowsDefault removes the policy. Replaces the obsolete EdgeHTML prelaunch area with a documented current control. Background apps use a separate policy; browser restart and managed-profile policy applicability require acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/startupboostenabled'
      SettingPresentation = @{
        AppliesTo = 'Device: installed Microsoft Edge startup boost; not per browser profile'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Microsoft Edge > edge://settings/system > Startup boost'
        GuiEffect = 'Mandatory policy fixes startup boost while configured. WindowsDefault removes this local override; other policy may still control the setting. Inspect edge://policy for effective source.'
        Requirements = @('Microsoft Edge 88 or later on Windows; RIDE currently declares Windows 11', 'Local machine policy; RIDE does not require Intune, domain membership or a cloud subscription')
        OtherSupportedChoices = @('Microsoft also supports a recommended policy that users can override; this ID implements the machine mandatory path only', 'Background applications use a separate control')
        ReferenceUris = @('https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/startupboostenabled')
      }
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableEdgePreload', 'EnableEdgePreload')
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
      ValueName = 'StartupBoostEnabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'application.edge-background-mode'
      Name = 'Microsoft Edge background applications policy'
      Kind = 'RegistryValue'
      Category = 'Application settings / Microsoft Edge'
      Description = 'Controls whether current Microsoft Edge can keep background applications running after its last browser window closes. Disabled writes 0; WindowsDefault removes the policy. This is an independently useful current replacement in the legacy preloading area; startup boost remains a separate control. Does not terminate existing processes or change Edge update scheduling.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/backgroundmodeenabled'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableEdgePreload', 'EnableEdgePreload')
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
      ValueName = 'BackgroundModeEnabled'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'application.edge-install-desktop-shortcut'
      Name = 'Microsoft Edge desktop shortcut creation upon installation'
      Kind = 'RegistryValue'
      Category = 'Application settings / Microsoft Edge'
      Description = 'Controls the default desktop-shortcut creation behavior when Microsoft Edge is installed, for all channels without a channel-specific override. Disabled writes 0; WindowsDefault removes the policy. Requires Edge Update 1.3.128.0 or later and has no effect on an already installed Edge browser. Replaces the obsolete Explorer DisableEdgeDesktopShortcutCreation preference; does not delete existing shortcuts or suppress every later update action.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-update-policies#createdesktopshortcutdefault'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      MigrationBatch = '2026-10-10-remaining-settings-2'
      LegacySelectors = @('DisableEdgeShortcutCreation', 'EnableEdgeShortcutCreation')
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
      ValueName = 'CreateDesktopShortcutDefault'
      ValueType = 'DWord'
      States = @{ Disabled = 0; Enabled = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $null; DefaultValue = $null; EffectiveDefault = 'Platform, installed components and managed policy determine the effective default; no RIDE baseline is assumed' } }
      Rollback = 'Exact'
    }
    @{
      Id = 'package.vscode'
      Name = 'Visual Studio Code (User Setup)'
      Kind = 'Package'
      Category = 'Software / Development'
      Description = 'Install or remove the official x64 Visual Studio Code (User Setup) distribution; preserve application data. Lifecycle acceptance is tracked in the application migration ledger.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'vscode'
      InstallerType = 'Exe'
      DisplayNamePattern = '^Microsoft Visual Studio Code(?: \(User\))?$'
      DownloadUri = 'https://update.code.visualstudio.com/api/update/win32-x64-user/stable/latest'
      DownloadProvider = 'VSCodeUpdateApi'
      Architecture = 'x64'
      ProductUri = 'https://code.visualstudio.com/'
      License = 'Microsoft Visual Studio Code license; bundled component notices'
      LicenseUri = 'https://code.visualstudio.com/license'
      InstallerArguments = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /MERGETASKS=!runcode'
      UninstallerArguments = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
      SuccessExitCodes = @(0)
      Rollback = 'Compensating'
      MigrationBatch = 'ApplicationsBatch1'
      AllowedDownloadHosts = @('vscode.download.prss.microsoft.com', 'az764295.vo.msecnd.net')
      RequiresDesktopExperience = $true
    }

    @{
      Id = 'package.firefox'
      Name = 'Mozilla Firefox'
      Kind = 'Package'
      Category = 'Software / Browsers'
      Description = 'Install or remove the official x64 Mozilla Firefox distribution; preserve application data. Lifecycle acceptance is tracked in the application migration ledger.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'firefox'
      InstallerType = 'Msi'
      UninstallerType = 'Exe'
      DisplayNamePattern = '^Mozilla Firefox(?:\s|$)'
      DownloadUri = 'https://product-details.mozilla.org/1.0/firefox_versions.json'
      DownloadProvider = 'MozillaVersionsJson'
      Architecture = 'x64'
      ProductUri = 'https://www.mozilla.org/firefox/'
      License = 'MPL-2.0 and bundled component licenses'
      LicenseUri = 'https://www.mozilla.org/en-US/MPL/2.0/'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/S'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
      MigrationBatch = 'ApplicationsBatch1'
      MozillaProduct = 'firefox'
      VersionKey = 'LATEST_FIREFOX_VERSION'
      AllowedDownloadHosts = @('archive.mozilla.org')
      RequiresDesktopExperience = $true
    }

    @{
      Id = 'package.sqlitebrowser'
      Name = 'DB Browser for SQLite'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Install or remove the official x64 DB Browser for SQLite distribution; preserve application data. Lifecycle acceptance is tracked in the application migration ledger.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'sqlitebrowser'
      InstallerType = 'Msi'
      DisplayNamePattern = '^DB Browser for SQLite(?:\s|$)'
      DownloadUri = 'https://api.github.com/repos/sqlitebrowser/sqlitebrowser/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      Architecture = 'x64'
      ProductUri = 'https://sqlitebrowser.org/'
      License = 'MPL-2.0 or GPL-3.0; bundled component notices'
      LicenseUri = 'https://github.com/sqlitebrowser/sqlitebrowser/blob/master/LICENSE'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
      MigrationBatch = 'ApplicationsBatch1'
      AssetPattern = '^DB\.Browser\.for\.SQLite-v[0-9.]+-win64\.msi$'
      RequiresDesktopExperience = $true
    }

    @{
      Id = 'package.autopsy'
      Name = 'Autopsy'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Install or remove the official x64 Autopsy distribution; preserve application data. Lifecycle acceptance is tracked in the application migration ledger.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'autopsy'
      InstallerType = 'Msi'
      DisplayNamePattern = '^Autopsy(?:\s|$)'
      DownloadUri = 'https://api.github.com/repos/sleuthkit/autopsy/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      Architecture = 'x64'
      ProductUri = 'https://www.autopsy.com/'
      License = 'Apache-2.0; bundled component notices'
      LicenseUri = 'https://github.com/sleuthkit/autopsy#licenses'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
      MigrationBatch = 'ApplicationsBatch1'
      AssetPattern = '^autopsy-[0-9.]+-64bit\.msi$'
      TagPrefix = 'autopsy-'
      RequiresDesktopExperience = $true
    }

    @{
      Id = 'package.chrome'
      Name = 'Google Chrome'
      Kind = 'Package'
      Category = 'Software / Browsers'
      Description = 'Install or remove the official stable x64 enterprise MSI, pinned to inspected bytes; preserve browser profiles. Browser language and policy configuration are separate choices.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'chrome'
      InstallerType = 'Msi'
      DisplayNamePattern = '^Google Chrome$'
      DownloadUri = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
      DownloadProvider = 'DirectHttps'
      PackageVersion = '155.0.8059.40'
      AssetName = 'GoogleChrome-155.0.8059.40-x64.msi'
      ExpectedSha256 = '32ba438dea18f0fed1ec621bfb274a2669adec67be2aa91d96b3cc6c64779276'
      Architecture = 'x64'
      ProductUri = 'https://chromeenterprise.google/download/'
      License = 'Google Chrome executable terms; bundled open-source component notices'
      LicenseUri = 'https://www.google.com/chrome/terms/'
      TermsUri = 'https://policies.google.com/terms'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
      DefaultVariant = 'installed'
      Variants = @{ installed = @{} }
      MigrationBatch = 'ApplicationsBatch1'
      RequiresDesktopExperience = $true
    }

    @{
      Id = 'package.signal'
      Name = 'Signal Desktop'
      Kind = 'Package'
      Category = 'Software / General'
      Description = 'Install or remove the official stable x64 current-user Signal Desktop distribution, bound to its publisher SHA-512; preserve message/profile data. Account linking and application language preferences remain user actions.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'signal'
      PreserveRoamingDirectory = 'Signal'
      PreservationProcessName = 'Signal'
      InstallerType = 'Exe'
      DisplayNamePattern = '^Signal(?: [0-9]+\.[0-9]+\.[0-9]+)?$'
      DownloadUri = 'https://updates.signal.org/desktop/latest.yml'
      DownloadProvider = 'SignalDesktopFeed'
      AllowedDownloadHosts = @('updates.signal.org')
      Architecture = 'x64'
      ProductUri = 'https://signal.org/download/'
      License = 'AGPL-3.0-only and bundled component notices'
      LicenseUri = 'https://github.com/signalapp/Signal-Desktop/blob/main/LICENSE'
      TermsUri = 'https://signal.org/legal/'
      InstallerArguments = '/S /currentuser'
      UninstallerArguments = '/S'
      SuccessExitCodes = @(0)
      Rollback = 'Compensating'
      DefaultVariant = 'installed'
      Variants = @{ installed = @{} }
      MigrationBatch = 'ApplicationsBatch1'
      RequiresDesktopExperience = $true
    }

    @{
      Id = 'package.thunderbird'
      Name = 'Mozilla Thunderbird'
      Kind = 'Package'
      Category = 'Software / General'
      Description = 'Install or remove official Release x64 Thunderbird in UK English for the current user. Run from non-elevated PowerShell; preserve mail profiles. Existing other editions require individual review.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'User'
      RequiresAdmin = $false
      RequiresUnelevatedUser = $true
      LocalAppDataInstallDirectory = 'Mozilla Thunderbird'
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'thunderbird'
      InstallerType = 'Exe'
      DisplayNamePattern = '^Mozilla Thunderbird(?: [0-9.]+)? \(x64 en-GB\)$'
      ConflictingDisplayNamePattern = '^Mozilla Thunderbird(?: |$)'
      PreserveRoamingDirectory = 'Thunderbird'
      PreservationProcessName = 'thunderbird'
      DownloadProvider = 'MozillaVersionsJson'
      DownloadUri = 'https://product-details.mozilla.org/1.0/thunderbird_versions.json'
      MozillaProduct = 'thunderbird'
      MozillaChannel = 'release'
      VersionKey = 'LATEST_THUNDERBIRD_VERSION'
      MozillaLocale = 'en-GB'
      Architecture = 'x64'
      AllowedDownloadHosts = @('archive.mozilla.org')
      ProductUri = 'https://www.thunderbird.net/en-US/'
      License = 'Mozilla Public License 2.0 and bundled component notices'
      LicenseUri = 'https://www.mozilla.org/en-US/MPL/2.0/'
      InstallerArguments = '/S /InstallDirectoryPath="{InstallDirectory}" /MaintenanceService=false /RegisterDefaultAgent=false /RemoveDistributionDir=false /PreventRebootRequired=true'
      UninstallerArguments = '/S'
      SuccessExitCodes = @(0)
      Rollback = 'Compensating'
      DefaultVariant = 'installed'
      Variants = @{ installed = @{} }
      MigrationBatch = 'ApplicationsBatch1'
      RequiresDesktopExperience = $true
    }

    @{
      Id = 'package.chainsaw'
      Name = 'Chainsaw'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Install or remove the official x64 Chainsaw distribution; preserve application data. Lifecycle acceptance is tracked in the application migration ledger.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'chainsaw'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Chainsaw$'
      DownloadUri = 'https://api.github.com/repos/WithSecureOpenSource/chainsaw/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      Architecture = 'x64'
      ProductUri = 'https://github.com/WithSecureOpenSource/chainsaw'
      License = 'GPL-3.0'
      LicenseUri = 'https://github.com/WithSecureOpenSource/chainsaw/blob/master/LICENCE'
      InstallerArguments = '/S'
      UninstallerArguments = '/S'
      SuccessExitCodes = @(0)
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      AssetPattern = '^chainsaw_x86_64-pc-windows-msvc\.zip$'
      PortableFormat = 'Zip'
      PortableFileName = ''
      RequiredFiles = @('chainsaw/chainsaw.exe', 'chainsaw/LICENCE')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{  } }
    }

    @{
      Id = 'package.hindsight'
      Name = 'Hindsight'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Install or remove the official x64 Hindsight distribution; preserve application data. Lifecycle acceptance is tracked in the application migration ledger.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'hindsight'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Hindsight$'
      DownloadUri = 'https://api.github.com/repos/RyanDFIR/hindsight/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      Architecture = 'x64'
      ProductUri = 'https://github.com/RyanDFIR/hindsight'
      License = 'Apache-2.0'
      LicenseUri = 'https://github.com/RyanDFIR/hindsight/blob/main/LICENSE.md'
      InstallerArguments = '/S'
      UninstallerArguments = '/S'
      SuccessExitCodes = @(0)
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      AssetPattern = '^hindsight_gui\.exe$'
      PortableFormat = 'File'
      PortableFileName = 'hindsight_gui.exe'
      RequiredFiles = @('hindsight_gui.exe')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{  } }
      RequiresDesktopExperience = $true
    }

    @{
      Id = 'package.cyberchef'
      Name = 'CyberChef (Offline)'
      Kind = 'Package'
      Category = 'Software / Analysis'
      Description = 'Install or remove the official offline CyberChef web artifact. Retain upstream notices and preserve user recipes and files; no browser is launched.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'cyberchef'
      InstallerType = 'Portable'
      DisplayNamePattern = '^CyberChef$'
      DownloadUri = 'https://api.github.com/repos/gchq/CyberChef/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      AssetPattern = '^CyberChef_[a-fA-F0-9]+\.zip$'
      Architecture = 'x64'
      ProductUri = 'https://github.com/gchq/CyberChef'
      License = 'Apache-2.0; bundled component licenses and notices'
      LicenseUri = 'https://github.com/gchq/CyberChef/blob/master/LICENSE'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      PortableFormat = 'Zip'
      RequiredFiles = @('CyberChef_v{version}.html')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
      RequiresDesktopExperience = $true
    }
    @{
      Id = 'package.putty'
      Name = 'PuTTY (Standalone x64)'
      Kind = 'Package'
      Category = 'Software / Utilities'
      Description = 'Install or remove the official standalone x64 PuTTY executable, preserving saved SSH sessions. This retains the legacy standalone distribution; no MSI edition is implicitly substituted.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'putty'
      InstallerType = 'Portable'
      DisplayNamePattern = '^PuTTY$'
      DownloadUri = 'https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html'
      DownloadProvider = 'PublisherLinkPage'
      ChecksumAssetPattern = '/sha256sums$'
      ChecksumMember = 'w64/putty.exe'
      AssetPattern = '/latest/w64/putty\.exe$'
      PageVersionPattern = 'latest release \((?<version>[0-9.]+)\)'
      VersionPattern = '/putty/(?<version>[0-9.]+)/w64/putty\.exe$'
      AllowedDownloadHosts = @('the.earth.li')
      Architecture = 'x64'
      ProductUri = 'https://www.chiark.greenend.org.uk/~sgtatham/putty/'
      License = 'MIT license'
      LicenseUri = 'https://www.chiark.greenend.org.uk/~sgtatham/putty/licence.html'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      PortableFormat = 'File'
      PortableFileName = 'putty.exe'
      RequiredFiles = @('putty.exe')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
      RequiresDesktopExperience = $true
    }

    @{
      Id = 'package.srum-dump'
      Name = 'SRUM Dump'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Deploy or remove the official standalone SRUM Dump executable; parsing evidence is a separate user action.'
      Scope = 'Machine'
      Handler = 'Package'
      PackageId = 'srum-dump'
      InstallerType = 'Portable'
      DisplayNamePattern = '^SRUM Dump$'
      DownloadUri = 'https://api.github.com/repos/MarkBaggett/srum-dump/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      Architecture = 'x64'
      ProductUri = 'https://github.com/MarkBaggett/srum-dump'
      License = 'GPL-3.0; retain publisher notices'
      LicenseUri = 'https://github.com/MarkBaggett/srum-dump/blob/master/LICENSE'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      PortableFormat = 'File'
      PortableFileName = 'srum_dump.exe'
      AssetPattern = '^srum_dump\.exe$'
      DefaultVariant = 'portable'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      RequiredFiles = @('srum_dump.exe')
      SuccessExitCodes = @(0)
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.srum-monkey'
      Name = 'SrumMonkey'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Deploy or remove the official standalone SrumMonkey executable; parsing evidence is a separate user action.'
      Scope = 'Machine'
      Handler = 'Package'
      PackageId = 'srum-monkey'
      InstallerType = 'Portable'
      DisplayNamePattern = '^SrumMonkey$'
      DownloadUri = 'https://api.github.com/repos/devgc/SrumMonkey/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      Architecture = 'x64'
      ProductUri = 'https://github.com/devgc/SrumMonkey'
      License = 'Apache-2.0; retain publisher notices'
      LicenseUri = 'https://github.com/devgc/SrumMonkey/blob/master/LICENSE'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      PortableFormat = 'File'
      PortableFileName = 'SrumMonkey_win64.exe'
      AssetPattern = '^SrumMonkey_win64\.exe$'
      DefaultVariant = 'portable'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      RequiredFiles = @('SrumMonkey_win64.exe')
      SuccessExitCodes = @(0)
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.dejsonlz4'
      Name = 'dejsonlz4'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Deploy or remove the official x86 dejsonlz4 archive; tool execution is a separate user action.'
      Scope = 'Machine'
      Handler = 'Package'
      PackageId = 'dejsonlz4'
      InstallerType = 'Portable'
      DisplayNamePattern = '^dejsonlz4$'
      DownloadUri = 'https://api.github.com/repos/avih/dejsonlz4/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      Architecture = 'x86'
      ProductUri = 'https://github.com/avih/dejsonlz4'
      License = 'BSD-2-Clause; retain publisher notices'
      LicenseUri = 'https://github.com/avih/dejsonlz4/blob/master/LICENSE'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      PortableFormat = 'Zip'
      AssetPattern = '^dejsonlz4\.v[0-9.]+\.zip$'
      DefaultVariant = 'portable'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      RequiredFiles = @('bin-win32/dejsonlz4.exe', 'LICENSE')
      SuccessExitCodes = @(0)
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.cylr'
      Name = 'CyLR'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Deploy or remove the official x86 CyLR archive; tool execution is a separate user action.'
      Scope = 'Machine'
      Handler = 'Package'
      PackageId = 'cylr'
      InstallerType = 'Portable'
      DisplayNamePattern = '^CyLR$'
      DownloadUri = 'https://api.github.com/repos/orlikoski/CyLR/releases/latest'
      DownloadProvider = 'GitHubReleaseApi'
      Architecture = 'x86'
      ProductUri = 'https://github.com/orlikoski/CyLR'
      License = 'GPL-3.0; retain publisher notices'
      LicenseUri = 'https://github.com/orlikoski/CyLR/blob/main/LICENSE'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      PortableFormat = 'Zip'
      AssetPattern = '^CyLR_win-x86\.zip$'
      DefaultVariant = 'portable'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      RequiredFiles = @('CyLR.exe')
      SuccessExitCodes = @(0)
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.caffeine'
      Name = 'Caffeine (Portable x86 and x64)'
      Kind = 'Package'
      Category = 'Software / Utilities'
      Description = 'Deploy or remove the publisher ZIP containing both Caffeine executables. Starting the application is a separate user action and can prevent sleep or locking. Version 1.98 is pinned by inspected archive hash; changed upstream bytes require review.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'caffeine'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Caffeine$'
      DownloadUri = 'https://www.zhornsoftware.co.uk/caffeine/caffeine.zip'
      DownloadProvider = 'DirectHttps'
      PackageVersion = '1.98'
      AssetName = 'caffeine-1.98.zip'
      ExpectedSha256 = '4a259c348e59eb51bbb75aac7fdcc798705496d575892ee1e01fff6970d5ba1c'
      Architecture = 'neutral'
      ProductUri = 'https://www.zhornsoftware.co.uk/caffeine/'
      License = 'Publisher freeware, including commercial use; retain supplied notices'
      LicenseUri = 'https://www.zhornsoftware.co.uk/'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      PortableFormat = 'Zip'
      RequiredFiles = @('caffeine32.exe', 'caffeine64.exe')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
      RequiresDesktopExperience = $true
    }
    @{
      Id = 'package.winscp'
      Name = 'WinSCP (Portable)'
      Kind = 'Package'
      Category = 'Software / General'
      Description = 'Deploy or remove the complete official WinSCP 6.5.7 portable distribution, verified against the publisher SHA-256. Preserve unowned WinSCP.ini/session files and existing registry configuration; no application launch or connection. The publisher supplies x86 binaries that run on x64 Windows.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'winscp'
      InstallerType = 'Portable'
      DisplayNamePattern = '^WinSCP$'
      DownloadUri = 'https://winscp.net/download/WinSCP-6.5.7-Portable.zip/download'
      DownloadProvider = 'WinSCPPortablePage'
      PackageVersion = '6.5.7'
      AllowedDownloadHosts = @('cdn.winscp.net')
      Architecture = 'x86'
      ProductUri = 'https://winscp.net/'
      License = 'GPL-3.0 and included icon-set notices, retained in license.txt'
      LicenseUri = 'https://winscp.net/eng/docs/license'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      PortableFormat = 'Zip'
      RequiredFiles = @('WinSCP.exe', 'WinSCP.com', 'license.txt', 'readme.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
      RequiresDesktopExperience = $true
    }
    @{
      Id = 'package.networkminer'
      Name = 'NetworkMiner (Free Portable Edition)'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Deploy or remove the complete official NetworkMiner 3.2 free-edition archive. Application execution and packet analysis are separate user actions requiring .NET Framework 4.8 or later. Preserve fingerprints, notices and user evidence; no capture driver or firewall rule is installed.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $false
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }; 'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' } }
      PackageId = 'networkminer'
      InstallerType = 'Portable'
      DisplayNamePattern = '^NetworkMiner$'
      DownloadUri = 'https://download.netresec.com/networkminer/NetworkMiner_3-2.zip'
      DownloadProvider = 'DirectHttps'
      PackageVersion = '3.2'
      AssetName = 'NetworkMiner_3-2.zip'
      ExpectedSha256 = 'daceec649fb4fe59b11e4a9e4ecd5f51c1dd37824280dfbeac67bec27b6b6d60'
      Architecture = 'neutral'
      ProductUri = 'https://www.netresec.com/?page=NetworkMiner'
      License = 'GPL-2.0; bundled fingerprint data has separate notices, all retained'
      LicenseUri = 'https://www.netresec.com/?page=NetworkMinerSourceCode'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'ApplicationsBatch2'
      PortableFormat = 'Zip'
      RequiredFiles = @('NetworkMiner_3-2/NetworkMiner.exe', 'NetworkMiner_3-2/PacketParser.dll', 'NetworkMiner_3-2/Fingerprints/mac-ages_LICENSE')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
      RequiresDesktopExperience = $true
    }
    @{
      Id = 'package.photocraft'
      Name = 'PhotoCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for image editing, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'photocraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/photocraft/releases/download/v0.7.0/photocraft-0.7.0-windows-x64.msi'
      PackageVersion = '0.7.0'
      AssetName = 'photocraft-0.7.0-windows-x64.msi'
      ExpectedSha256 = 'af959a169ba0b93bdcec4df0e9dfdbac365b7759d3d74b06c3f8f96ed45ff9a0'
      DisplayNamePattern = '^PhotoCraft$'
      ProductUri = 'https://getartcraft.com/apps/photocraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/photocraft/blob/v0.7.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/photocraft/blob/v0.7.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/photocraft/releases/tag/v0.7.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.vectorcraft'
      Name = 'VectorCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for vector illustration, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'vectorcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/vectorcraft/releases/download/v0.9.0/vectorcraft-0.9.0-windows-x64.msi'
      PackageVersion = '0.9.0'
      AssetName = 'vectorcraft-0.9.0-windows-x64.msi'
      ExpectedSha256 = 'de590a69ac3345f32586efa1b608f868c5ca71cde5646aed715054c68da73c23'
      DisplayNamePattern = '^VectorCraft$'
      ProductUri = 'https://getartcraft.com/apps/vectorcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/vectorcraft/blob/v0.9.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/vectorcraft/blob/v0.9.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/vectorcraft/releases/tag/v0.9.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.filmcraft'
      Name = 'FilmCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for video editing, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'filmcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/filmcraft/releases/download/v0.6.0/filmcraft-0.6.0-windows-x64.msi'
      PackageVersion = '0.6.0'
      AssetName = 'filmcraft-0.6.0-windows-x64.msi'
      ExpectedSha256 = '7cd23b18a719884ef8cd06a2dfb2e362fc165e03037c62a4548e900136ef8e9f'
      DisplayNamePattern = '^FilmCraft$'
      ProductUri = 'https://getartcraft.com/apps/filmcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/filmcraft/blob/v0.6.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/filmcraft/blob/v0.6.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/filmcraft/releases/tag/v0.6.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.lightcraft'
      Name = 'LightCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for photo library management and RAW development, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'lightcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/lightcraft/releases/download/v0.6.0/lightcraft-0.6.0-windows-x64.msi'
      PackageVersion = '0.6.0'
      AssetName = 'lightcraft-0.6.0-windows-x64.msi'
      ExpectedSha256 = 'cb61c2c8d8d5fe7f11b0dcdc9eebe1fc180f514d58b43018aacda9444b8a4772'
      DisplayNamePattern = '^LightCraft$'
      ProductUri = 'https://getartcraft.com/apps/lightcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/lightcraft/blob/v0.6.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/lightcraft/blob/v0.6.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/lightcraft/releases/tag/v0.6.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.pdfcraft'
      Name = 'PdfCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for PDF reading and editing, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'pdfcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/pdfcraft/releases/download/v0.6.0/pdfcraft-0.6.0-windows-x64.msi'
      PackageVersion = '0.6.0'
      AssetName = 'pdfcraft-0.6.0-windows-x64.msi'
      ExpectedSha256 = '528b2fec067ea907894d67c7c686d8023aa943a32941a5586ee402070af458b3'
      DisplayNamePattern = '^PdfCraft$'
      ProductUri = 'https://getartcraft.com/apps/pdfcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/pdfcraft/blob/v0.6.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/pdfcraft/blob/v0.6.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/pdfcraft/releases/tag/v0.6.0'
      InstallerArguments = '/qn /norestart ALLUSERS=1'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.effectcraft'
      Name = 'EffectCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for motion graphics and visual effects, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'effectcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/effectcraft/releases/download/v0.8.0/effectcraft-0.8.0-windows-x64.msi'
      PackageVersion = '0.8.0'
      AssetName = 'effectcraft-0.8.0-windows-x64.msi'
      ExpectedSha256 = '868ddd1d0682bc3f31d82524cc66059d03d6750c1cdb96c9bbd73952b921f65b'
      DisplayNamePattern = '^EffectCraft$'
      ProductUri = 'https://getartcraft.com/apps/effectcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/effectcraft/blob/v0.8.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/effectcraft/blob/v0.8.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/effectcraft/releases/tag/v0.8.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.designcraft'
      Name = 'DesignCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for page layout and publishing, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'designcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/designcraft/releases/download/v0.6.0/designcraft-0.6.0-windows-x64.msi'
      PackageVersion = '0.6.0'
      AssetName = 'designcraft-0.6.0-windows-x64.msi'
      ExpectedSha256 = 'bbbbfad780d5e81c9d8c0e5922642b835bcdfa8b4bb3da0f01252f3986ae8290'
      DisplayNamePattern = '^DesignCraft$'
      ProductUri = 'https://getartcraft.com/apps/designcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/designcraft/blob/v0.6.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/designcraft/blob/v0.6.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/designcraft/releases/tag/v0.6.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.wordcraft'
      Name = 'WordCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for word processing, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'wordcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/wordcraft/releases/download/v0.5.0/wordcraft-0.5.0-windows-x64.msi'
      PackageVersion = '0.5.0'
      AssetName = 'wordcraft-0.5.0-windows-x64.msi'
      ExpectedSha256 = '47eee8ccf44158fce76d0431b27b857ca15342f3c662cf4fa77aee328a2f1255'
      DisplayNamePattern = '^WordCraft$'
      ProductUri = 'https://getartcraft.com/apps/wordcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/wordcraft/blob/v0.5.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/wordcraft/blob/v0.5.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/wordcraft/releases/tag/v0.5.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.soundcraft'
      Name = 'SoundCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for audio recording and editing, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'soundcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/soundcraft/releases/download/v0.5.0/soundcraft-0.5.0-windows-x64.msi'
      PackageVersion = '0.5.0'
      AssetName = 'soundcraft-0.5.0-windows-x64.msi'
      ExpectedSha256 = '5bfed941e4fc9bb8e9e9474805773fa3a5c38a2f1848b8a246265cb2d7215773'
      DisplayNamePattern = '^SoundCraft$'
      ProductUri = 'https://getartcraft.com/apps/soundcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/soundcraft/blob/v0.5.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/soundcraft/blob/v0.5.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/soundcraft/releases/tag/v0.5.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.deckcraft'
      Name = 'DeckCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for presentations, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'deckcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/deckcraft/releases/download/v0.5.0/deckcraft-0.5.0-windows-x64.msi'
      PackageVersion = '0.5.0'
      AssetName = 'deckcraft-0.5.0-windows-x64.msi'
      ExpectedSha256 = '71bd36cba92aa6fe877274fa7d33d124efbd8179a9fd5af5f240cc2965d476b1'
      DisplayNamePattern = '^DeckCraft$'
      ProductUri = 'https://getartcraft.com/apps/deckcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/deckcraft/blob/v0.5.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/deckcraft/blob/v0.5.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/deckcraft/releases/tag/v0.5.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.cadcraft'
      Name = 'CADCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for computer-aided design and drafting, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'cadcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/cadcraft/releases/download/v0.5.0/cadcraft-0.5.0-windows-x64.msi'
      PackageVersion = '0.5.0'
      AssetName = 'cadcraft-0.5.0-windows-x64.msi'
      ExpectedSha256 = '3533bca1af65191a7c9c9408e7e4f9049293a58d7f1586c8bf0a44697a88716c'
      DisplayNamePattern = '^CADCraft$'
      ProductUri = 'https://getartcraft.com/apps/cadcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/cadcraft/blob/v0.5.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/cadcraft/blob/v0.5.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/cadcraft/releases/tag/v0.5.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.gridcraft'
      Name = 'GridCraft'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned standalone x64 MSI for spreadsheets, with an embedded application payload. Early release; Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'gridcraft'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/gridcraft/releases/download/v0.5.0/gridcraft-0.5.0-windows-x64.msi'
      PackageVersion = '0.5.0'
      AssetName = 'gridcraft-0.5.0-windows-x64.msi'
      ExpectedSha256 = '3aac5a2ac3f2c5b9c23a737e619aeccb1e698ccbb5b732e14c805f74d826b9a9'
      DisplayNamePattern = '^GridCraft$'
      ProductUri = 'https://getartcraft.com/apps/gridcraft'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/gridcraft/blob/v0.5.0/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/gridcraft/blob/v0.5.0/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/gridcraft/releases/tag/v0.5.0'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.artcraft-launcher'
      Name = 'ArtCraft Launcher'
      Kind = 'Package'
      Category = 'Software / Artcraft'
      Description = 'Pinned current-user x64 MSI containing the complete launcher. The launcher downloads apps and updates separately when used; use the individual app packages for offline installers. Windows 11 lifecycle acceptance is pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'artcraft-launcher'
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/storytold/craft-launcher/releases/download/v0.2.1/artcraft-launcher-0.2.1-windows-x64.msi'
      PackageVersion = '0.2.1'
      AssetName = 'artcraft-launcher-0.2.1-windows-x64.msi'
      ExpectedSha256 = '891549bab5e8bef98ba9fb55a7ab19582aabcaf40946194c94237c3c6b9137e1'
      DisplayNamePattern = '^ArtCraft\ Launcher$'
      ProductUri = 'https://getartcraft.com/apps'
      License = 'MIT OR Apache-2.0 for code; bundled assets retain their notices; Artcraft branding has separate terms'
      LicenseUri = 'https://github.com/storytold/craft-launcher/blob/v0.2.1/README.md#license-and-credits'
      TermsUri = 'https://github.com/storytold/craft-launcher/blob/v0.2.1/docs/brand/LICENSE-brand.txt'
      RecoveryUri = 'https://github.com/storytold/craft-launcher/releases/tag/v0.2.1'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
    }
  )
  Groups = @(
    @{
      Id = 'solution.artcraft-apps'
      Name = 'Artcraft creative apps'
      Category = 'Software / Groups'
      Description = 'The twelve standalone Crafting Apps, without the optional online launcher. Individual x64 MSI packages remain pending Windows 11 lifecycle acceptance.'
      Members = @('package.photocraft', 'package.vectorcraft', 'package.filmcraft', 'package.lightcraft', 'package.pdfcraft', 'package.effectcraft', 'package.designcraft', 'package.wordcraft', 'package.soundcraft', 'package.deckcraft', 'package.cadcraft', 'package.gridcraft')
      Actions = @('Install', 'Uninstall')
      Rollback = 'Compensating'
    }
    @{
      Id = 'solution.analyst-basics'
      Name = 'Analyst basics'
      Category = 'Software / Groups'
      Description = 'A small utility bundle with 7-Zip and Notepad++.'
      Members = @('package.7zip', 'package.notepadpp')
      Actions = @('Install', 'Uninstall')
      Rollback = 'Compensating'
    }
    @{
      Id = 'solution.git-development'
      Name = 'Git and standalone Git LFS'
      Category = 'Software / Groups'
      Description = 'Install Git before standalone Git LFS; remove them in reverse order.'
      Members = @('package.git-for-windows', 'package.git-lfs')
      Actions = @('Install', 'Uninstall')
      Rollback = 'Compensating'
    }
  )
}
