# Authoritative operation/group metadata. SchemaVersion 1; edit here and regenerate docs/OPERATIONS.md. Targets, scope, states, sources, and rollback limits are declared per operation.
# Owner: RIDE-Windows maintainers. Keep values as declarative data.
# Versioning: SchemaVersion governs the data contract; no independent script CLI/version.

@{
  SchemaVersion = 1
  Operations = @(
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
      Description = 'Show file extensions for registered file types in File Explorer.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/common-file-name-extensions-in-windows'
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
