@{
  SchemaVersion = 1
  Operations = @(
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
      Name = 'Voice activation access for apps'
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
      Name = 'Voice activation above lock for apps'
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
      Description = 'Show file extensions for registered file types in File Explorer.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/common-file-name-extensions-in-windows'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
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
      Name = 'Action Center notifications'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Disable Action Center and toast notifications for the current user.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-taskbar'
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
      Name = 'Toast notifications'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Disable toast notifications for the current user.'
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
      Id = 'package.7zip'
      Name = '7-Zip'
      Kind = 'Package'
      Category = 'Software / Utilities'
      Description = 'Install or remove the current 64-bit 7-Zip release.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }
        'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }
      }
      PackageId = '7zip'
      InstallerType = 'Exe'
      DisplayNamePattern = '^7-Zip'
      DownloadUri = 'https://www.7-zip.org/'
      ProductUri = 'https://www.7-zip.org/'
      InstallerArguments = '/S'
      UninstallerArguments = '/S'
      Rollback = 'Compensating'
    }
    @{
      Id = 'package.notepadpp'
      Name = 'Notepad++'
      Kind = 'Package'
      Category = 'Software / Utilities'
      Description = 'Install or remove the current 64-bit Notepad++ release.'
      SupportedTargets = @('Windows 11', 'Windows Server 2025')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }
        'Windows Server 2025' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Not installed in the default Windows image' }
      }
      PackageId = 'notepadpp'
      InstallerType = 'Exe'
      DisplayNamePattern = '^Notepad\+\+'
      DownloadUri = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest/download/npp.installer.x64.exe'
      ProductUri = 'https://notepad-plus-plus.org/'
      InstallerArguments = '/S'
      UninstallerArguments = '/S'
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
  )
  Groups = @(
    @{
      Id = 'solution.analyst-basics'
      Name = 'Analyst basics'
      Category = 'Software / Groups'
      Description = 'A small utility bundle with 7-Zip and Notepad++.'
      Members = @('package.7zip', 'package.notepadpp')
      Actions = @('Install', 'Uninstall')
      Rollback = 'Compensating'
    }
  )
}
