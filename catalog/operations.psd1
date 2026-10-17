# Authoritative operation/group metadata. SchemaVersion 1; edit here and regenerate docs/OPERATIONS.md. Targets, scope, states, sources, and rollback limits are declared per operation.
# Owner: RIDE-Windows maintainers. Keep values as declarative data.
# Versioning: SchemaVersion governs the data contract; no independent script CLI/version.

@{
  SchemaVersion = 1
  Operations = @(
    @{
      Id = 'app.xbox-tcui'
      Name = 'Xbox TCUI Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Xbox TCUI registration action in batch 3. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.Xbox.TCUI'
      PackageFamilyName = 'Microsoft.Xbox.TCUI_8wekyb3d8bbwe'
      PolicySelectionId = 'XboxTCUI'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch320261014'
    }
    @{
      Id = 'app.xbox-identity-provider'
      Name = 'Xbox Identity Provider Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Xbox Identity Provider registration action in batch 3. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.XboxIdentityProvider'
      PackageFamilyName = 'Microsoft.XboxIdentityProvider_8wekyb3d8bbwe'
      PolicySelectionId = 'XboxIdentityProvider'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch320261014'
    }
    @{
      Id = 'app.xbox-speech-overlay'
      Name = 'Xbox Speech to Text Overlay Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Xbox Speech to Text Overlay registration action in batch 3. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.XboxSpeechToTextOverlay'
      PackageFamilyName = 'Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe'
      PolicySelectionId = 'XboxSpeechToTextOverlay'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch320261014'
    }
    @{
      Id = 'app.xbox'
      Name = 'Xbox app Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Xbox app registration action in batch 3. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.GamingApp'
      PackageFamilyName = 'Microsoft.GamingApp_8wekyb3d8bbwe'
      PolicySelectionId = 'GamingApp'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch320261014'
    }
    @{
      Id = 'app.game-bar'
      Name = 'Game Bar Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Game Bar registration action in batch 3. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.XboxGamingOverlay'
      PackageFamilyName = 'Microsoft.XboxGamingOverlay_8wekyb3d8bbwe'
      PolicySelectionId = $null
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch320261014'
    }
    @{
      Id = 'app.quick-assist'
      Name = 'Quick Assist Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Quick Assist registration action in batch 2C. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'MicrosoftCorporationII.QuickAssist'
      PackageFamilyName = 'MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe'
      PolicySelectionId = 'QuickAssist'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2C20261014'
    }
    @{
      Id = 'app.sticky-notes'
      Name = 'Sticky Notes Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Sticky Notes registration action in batch 2C. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.MicrosoftStickyNotes'
      PackageFamilyName = 'Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe'
      PolicySelectionId = 'MicrosoftStickyNotes'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2C20261014'
    }
    @{
      Id = 'app.outlook'
      Name = 'Outlook Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Outlook registration action in batch 2C. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.OutlookForWindows'
      PackageFamilyName = 'Microsoft.OutlookForWindows_8wekyb3d8bbwe'
      PolicySelectionId = 'OutlookForWindows'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2C20261014'
    }
    @{
      Id = 'app.todo'
      Name = 'To Do Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user To Do registration action in batch 2C. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.Todos'
      PackageFamilyName = 'Microsoft.Todos_8wekyb3d8bbwe'
      PolicySelectionId = 'Todo'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2C20261014'
    }
    @{
      Id = 'app.photos'
      Name = 'Photos Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Photos registration action in batch 2B. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.Windows.Photos'
      PackageFamilyName = 'Microsoft.Windows.Photos_8wekyb3d8bbwe'
      PolicySelectionId = 'Photos'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2B20261014'
    }
    @{
      Id = 'app.paint'
      Name = 'Paint Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Paint registration action in batch 2B. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.Paint'
      PackageFamilyName = 'Microsoft.Paint_8wekyb3d8bbwe'
      PolicySelectionId = 'Paint'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2B20261014'
    }
    @{
      Id = 'app.camera'
      Name = 'Camera Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Camera registration action in batch 2B. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.WindowsCamera'
      PackageFamilyName = 'Microsoft.WindowsCamera_8wekyb3d8bbwe'
      PolicySelectionId = 'WindowsCamera'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2B20261014'
    }
    @{
      Id = 'app.media-player'
      Name = 'Media Player Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Media Player registration action in batch 2B. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.ZuneMusic'
      PackageFamilyName = 'Microsoft.ZuneMusic_8wekyb3d8bbwe'
      PolicySelectionId = 'MediaPlayer'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2B20261014'
    }
    @{
      Id = 'app.sound-recorder'
      Name = 'Sound Recorder Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Sound Recorder registration action in batch 2B. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.WindowsSoundRecorder'
      PackageFamilyName = 'Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe'
      PolicySelectionId = 'WindowsSoundRecorder'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2B20261014'
    }
    @{
      Id = 'app.calculator'
      Name = 'Calculator Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Calculator registration action in batch 2A. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.WindowsCalculator'
      PackageFamilyName = 'Microsoft.WindowsCalculator_8wekyb3d8bbwe'
      PolicySelectionId = 'WindowsCalculator'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2A20261014'
    }
    @{
      Id = 'app.notepad'
      Name = 'Notepad Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Notepad registration action in batch 2A. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.WindowsNotepad'
      PackageFamilyName = 'Microsoft.WindowsNotepad_8wekyb3d8bbwe'
      PolicySelectionId = 'WindowsNotepad'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2A20261014'
    }
    @{
      Id = 'app.snipping-tool'
      Name = 'Snipping Tool Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Snipping Tool registration action in batch 2A. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.ScreenSketch'
      PackageFamilyName = 'Microsoft.ScreenSketch_8wekyb3d8bbwe'
      PolicySelectionId = 'ScreenSketch'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2A20261014'
    }
    @{
      Id = 'app.terminal'
      Name = 'Terminal Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional intended-desktop-user Terminal registration action in batch 2A. Captured exact family; known protection/type, other-app consumers, policy, desktop and retained-source checks required. No downloads, shared framework removal, AllUsers changes or deprovisioning. Missing removability/type/source proof and pending target acceptance refuse changes; IsPartOfSystem stays visibly unknown under the reviewed identity rule. App data and previous versions are not guaranteed recovery.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.WindowsTerminal'
      PackageFamilyName = 'Microsoft.WindowsTerminal_8wekyb3d8bbwe'
      PolicySelectionId = 'WindowsTerminal'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreBatch2A20261014'
    }
    @{
      Id = 'app.clipchamp'
      Name = 'Clipchamp Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional current-desktop-user registration uninstall and retained-payload reinstall for Clipchamp. Reviewed exact identity, known removability/runtime types, policy, user/session and usable local source checks are required; IsPartOfSystem stays visibly unknown. No downloads, AllUsers removal, image deprovisioning or device policy changes. Native interactive/lifecycle acceptance pending; normal mutation is blocked. App data and old versions are not recoverable by this contract.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Clipchamp.Clipchamp'
      PackageFamilyName = 'Clipchamp.Clipchamp_yxz26nhyzhsrt'
      PolicySelectionId = 'Clipchamp'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreConsumerApps20261014'
    }
    @{
      Id = 'app.news'
      Name = 'News Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional current-desktop-user registration uninstall and retained-payload reinstall for News. Reviewed exact identity, known removability/runtime types, policy, user/session and usable local source checks are required; IsPartOfSystem stays visibly unknown. No downloads, AllUsers removal, image deprovisioning or device policy changes. Native interactive/lifecycle acceptance pending; normal mutation is blocked. App data and old versions are not recoverable by this contract.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.BingNews'
      PackageFamilyName = 'Microsoft.BingNews_8wekyb3d8bbwe'
      PolicySelectionId = 'BingNews'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreConsumerApps20261014'
    }
    @{
      Id = 'app.weather'
      Name = 'Weather Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional current-desktop-user registration uninstall and retained-payload reinstall for Weather. Reviewed exact identity, known removability/runtime types, policy, user/session and usable local source checks are required; IsPartOfSystem stays visibly unknown. No downloads, AllUsers removal, image deprovisioning or device policy changes. Native interactive/lifecycle acceptance pending; normal mutation is blocked. App data and old versions are not recoverable by this contract.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.BingWeather'
      PackageFamilyName = 'Microsoft.BingWeather_8wekyb3d8bbwe'
      PolicySelectionId = 'BingWeather'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreConsumerApps20261014'
    }
    @{
      Id = 'app.solitaire'
      Name = 'Solitaire Store registration (experimental)'
      Kind = 'StoreApp'
      Category = 'Windows components / Store apps'
      Description = 'Optional current-desktop-user registration uninstall and retained-payload reinstall for Solitaire. Reviewed exact identity, known removability/runtime types, policy, user/session and usable local source checks are required; IsPartOfSystem stays visibly unknown. No downloads, AllUsers removal, image deprovisioning or device policy changes. Native interactive/lifecycle acceptance pending; normal mutation is blocked. App data and old versions are not recoverable by this contract.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Uninstall', 'Reinstall')
      Handler = 'StoreApp'
      TargetDefaults = @{}
      AppxName = 'Microsoft.MicrosoftSolitaireCollection'
      PackageFamilyName = 'Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe'
      PolicySelectionId = 'MicrosoftSolitaireCollection'
      RequireKnownProtectionFlags = $true
      ProtectionRule = 'ReviewedIdentityRemovabilityV1'
      ReinstallSource = 'RetainedManifestOnly'
      Rollback = 'BestEffort'
      MigrationBatch = 'StoreConsumerApps20261014'
    }
    @{
      Id = 'windows.local-password-maximum-age'
      Name = 'Local-account maximum password age (experimental)'
      Kind = 'LocalPasswordMaximumAge'
      Category = 'Windows settings / Accounts'
      Description = 'Advanced machine/admin maximum password age for the local SAM account authority. NoExpiry means Never expires; Days1 through Days999 are explicit day choices from a bounded catalog range, checked against the current minimum age. Uses local NetUserModalsSet level 1002 to change only maximum-age seconds, with complete nonsecret modal context capture, local SAM SID identity, drift checks and exact prior raw-seconds recovery. Domain controllers and unknown computer roles are refused. No password, per-account never-expire flag, complexity, minimum age, length, history, lockout or domain policy is changed. The API reports currently applied local SAM data, not local GPO definitions or managed source; Not defined/removal is not invented. No universal 42-day/default preset or recommended-profile weakening. Native, GUI, managed-precedence and target acceptance remain pending; normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-password-age'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'LocalPasswordMaximumAge'
      States = @{ NoExpiry = 0 }
      StateRange = @{ Prefix = 'Days'; Minimum = 1; Maximum = 999 }
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsLocalPasswordAge20261013'
      LegacySelectors = @('DisablePasswordPolicy', 'EnablePasswordPolicy')
      SettingPresentation = @{
        AppliesTo = 'Whole device local SAM account authority; domain controllers refused'
        Behavior = 'EnforcedPolicy'
        GuiEffect = 'Maximum password age choice in Local Security Policy; currently applied SAM value is distinct from policy definitions and provenance'
        GuiPath = 'Local Security Policy > Account Policies > Password Policy > Maximum password age'
        Requirements = @('Administrator; workstation or standalone/member server with verified local SAM identity', 'Explicit day choice must exceed current minimum age; no implicit minimum-age adjustment', 'Local policy GUI/edition and managed reapplication need target acceptance; no RIDE/cloud membership is required')
        OtherSupportedChoices = @('NoExpiry differs from Not defined; Days1..Days999 are finite catalog-derived states', 'Complexity remains a separate pending control; per-account expiry and domain password policies are untouched', 'Exact field recovery does not restore changed passwords; unrelated modal or authority changes can block recovery')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsset', 'https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_1002', 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-password-age')
      }
    }
    @{
      Id = 'windows.audio-service'
      Name = 'Windows Audio service (experimental)'
      Kind = 'WindowsService'
      Category = 'Windows settings / Audio'
      Description = 'Advanced whole-device Windows Audio service control, separate from playback-device mute. AutomaticRunning configures Automatic/running; ManualStopped retains the legacy Manual/stopped intent without force-stopping dependents or substituting Disabled. Required services must already be running before start/resume; active dependents and load-order group dependencies block transitions before configuration changes. Only Audiosrv is changed; dependencies are read and compared, never configured or restored. Capture and restore its exact prior startup/runtime plus SCM and typed literal delay state. This is not current-user mute or proof of silence/recovered playback. No AudioEndpointBuilder, device, volume, microphone, application or default-device changes. Runtime/dependency, GUI, audio and target acceptance remain pending; normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/windows-audio-architecture'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'WindowsService'
      ServiceName = 'Audiosrv'
      PreserveDelayedAutoStart = $true
      RefuseDependencyChanges = $true
      States = @{
        AutomaticRunning = @{ StartupType = 'Automatic'; Status = 'Running' }
        ManualStopped = @{ StartupType = 'Manual'; Status = 'Stopped' }
      }
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsWindowsAudioService20261013'
      LegacySelectors = @('EnableAudio', 'DisableAudio')
      SettingPresentation = @{
        AppliesTo = 'Whole device and all sessions; Windows Audio service configuration/runtime'
        Behavior = 'Preference'
        GuiEffect = 'Advanced Services control; Manual is not Disabled and this is not a playback-device mute checkbox'
        GuiPath = 'Services > Windows Audio > Startup type and Service status'
        Requirements = @('Administrator; existing Audiosrv, readable service configuration and bounded stable dependency inspection', 'Required services must already run; active dependents or load-order group dependencies require separate review', 'Do not edit services concurrently; no automatic dependency repair, component install or extra RIDE subscription')
        OtherSupportedChoices = @('Selected playback endpoint Mute/Unmute remains a separate pending intended-user operation', 'Manual/stopped may later be started by another caller; no continuous enforcement or all-audio suppression guarantee', 'Saved restore changes only the captured primary service; dependent services are never adopted or replayed')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/windows-audio-architecture', 'https://learn.microsoft.com/en-us/powershell/scripting/samples/managing-services')
      }
    }
    @{
      Id = 'windows.shutdown-event-tracker-policy'
      Name = 'Shutdown Event Tracker display policy (experimental)'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Server'
      Description = 'Advanced paired machine policy for Display Shutdown Event Tracker: Disabled preserves the existing display choice; Always, ServerOnly and WorkstationOnly explicitly coordinate enablement and display selection. WindowsDefault removes both declared overrides; the legacy enable selector removed only enablement, so this is not an identical replay of every reverse. Capture both values and exact prior types/absence before mutation; restore recovers the captured pair. This does not shut down/restart Windows, erase event records, change persistent timestamps or state-data reporting. Local policy only; actual shutdown/logon/managed precedence and Server acceptance remain pending, with normal apply blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-reliability#shutdownreason'
      SupportedTargets = @()
      CandidateTargets = @('Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      RegistryValues = @(
        @{ Key = 'Display'; RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability'; ValueName = 'ShutdownReasonUI'; ValueType = 'DWord' }
        @{ Key = 'Enabled'; RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability'; ValueName = 'ShutdownReasonOn'; ValueType = 'DWord' }
      )
      States = @{
        Disabled = @{ Display = @{ KeepCurrent = $true }; Enabled = 0 }
        Always = @{ Display = 1; Enabled = 1 }
        WorkstationOnly = @{ Display = 2; Enabled = 1 }
        ServerOnly = @{ Display = 3; Enabled = 1 }
        WindowsDefault = @{ Display = $null; Enabled = $null }
      }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsShutdownTracker20261013'
      LegacySelectors = @('DisableShutdownTracker', 'EnableShutdownTracker')
      SettingPresentation = @{
        AppliesTo = 'Whole device; conditional shutdown reason prompt policy'
        Behavior = 'EnforcedPolicy'
        GuiEffect = 'Group Policy dropdown for Display Shutdown Event Tracker, with scope selection distinct from whether this server currently prompts'
        GuiPath = 'Computer Configuration > Administrative Templates > System > Display Shutdown Event Tracker'
        Requirements = @('Administrator; verified target shutdown UI and policy consumer', 'Local ADMX/CSP presence does not establish Windows Server desktop/Core or client support here', 'No shutdown/restart or forced policy refresh performed; content/event history remains intact')
        OtherSupportedChoices = @('Disabled writes only enablement=0 and retains even custom/absent display data', 'Always=1, WorkstationOnly=2 and ServerOnly=3 require enablement=1; ServerOnly on a workstation differs from Disabled', 'WindowsDefault removes both overrides; exact saved restore recovers the actual prior pair, not a guessed platform default')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-reliability#shutdownreason', 'https://learn.microsoft.com/en-us/windows/win32/shutdown/shutdown-event-tracker')
      }
    }
    @{
      Id = 'windows.server-manager-startup-policy'
      Name = 'Server Manager automatic startup policy (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Server'
      Description = 'Advanced machine policy for Server Manager automatic display at server logon, separate from the console preference. Suppressed enables Do not display Server Manager automatically at logon (1); AutomaticStartup explicitly disables that policy (0); WindowsDefault removes the override so Windows and the console preference govern startup, matching the legacy reverse. This does not launch/close Server Manager, change tasks or install a component. Saved restore recovers literal prior type/data/absence. Server desktop/logon/precedence acceptance remains pending; normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-servermanager#donotlaunchservermanager'
      SupportedTargets = @()
      CandidateTargets = @('Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager'
      ValueName = 'DoNotOpenAtLogon'
      ValueType = 'DWord'
      States = @{ Suppressed = 1; AutomaticStartup = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsServerManager20261013'
      LegacySelectors = @('HideServerManagerOnLogin', 'ShowServerManagerOnLogin')
      SettingPresentation = @{
        AppliesTo = 'Whole server; applicable interactive Server Manager logon behavior'
        Behavior = 'EnforcedPolicy'
        GuiEffect = 'Group Policy choice, separate from the Server Manager Properties startup preference; does not start the console now'
        GuiPath = 'Computer Configuration > Administrative Templates > System > Server Manager > Do not display Server Manager automatically at logon'
        Requirements = @('Administrator; Server Manager on a verified Windows Server desktop/logon environment', 'Server Core and client-side policy template presence do not establish local Server Manager applicability', 'No extra RIDE account, cloud enrollment or subscription; Windows/component licensing remains separate')
        OtherSupportedChoices = @('Suppressed=1, AutomaticStartup=0 and override removal differ', 'WindowsDefault does not reset the console preference', 'Existing local/domain management can override configured policy; effective source is not inspected')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-servermanager#donotlaunchservermanager', 'https://learn.microsoft.com/en-us/windows-server/administration/server-manager/server-manager')
      }
    }
    @{
      Id = 'windows.media-radio-preset-retrieval-policy'
      Name = 'Prevent Radio Station Preset Retrieval (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Media'
      Description = 'Prevent Windows Media Player radio preset retrieval and related preset display/update behavior when the legacy component consumes this policy. Advanced conditional User policy, not a general media-network block or verified current component effect. Blocked enables the preventive policy; PolicyDisabled writes its explicit disabled value; WindowsDefault removes the override, matching the legacy reverse. Saved restore recovers prior type/data/absence only. No player installation, playback test, license-store mutation or automatic DRM inclusion in media metadata guidance. Effective policy/source and target acceptance remain pending; normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventradiopresetsretrieval'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
      ValueName = 'PreventRadioPresetsRetrieval'
      ValueType = 'DWord'
      States = @{ Blocked = 1; PolicyDisabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsMediaPolicies20261013'
      LegacySelectors = @('DisableMediaOnlineAccess', 'EnableMediaOnlineAccess')
      SettingPresentation = @{
        AppliesTo = 'Current user; conditional Windows Media Player radio feature'
        Behavior = 'EnforcedPolicy'
        GuiEffect = 'Group Policy choice for Prevent Radio Station Preset Retrieval; current component behavior is unverified'
        GuiPath = 'User Configuration > Windows Components > Windows Media Player > Prevent Radio Station Preset Retrieval'
        Requirements = @('Intended user without elevation; installed/enabled consuming player and verified current radio feature; local ADMX declares pre-Vista applicability', 'Microsoft CSP lists Pro, Enterprise, Education and IoT Enterprise; Home and Server are not accepted here', 'No extra RIDE membership, cloud account or subscription for local configuration; payload/service/license availability is separate')
        OtherSupportedChoices = @('Blocked=1, PolicyDisabled=0 and override removal differ', 'Separate from CD/DVD and music metadata policies, DRM, streaming protocols and generic app radio privacy', 'Registry recovery does not restore remote services, content licenses or successful playback')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventradiopresetsretrieval')
      }
    }
    @{
      Id = 'windows.media-drm-online-access-policy'
      Name = 'Prevent Windows Media DRM Internet Access (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Media'
      Description = 'Prevent Windows Media DRM online/intranet license acquisition, security upgrades and license restoration when a consuming backend is present. This can prevent new licenses and security upgrades; it does not promise that existing licensed content stops playing. Advanced conditional Machine policy, not a general media-network block or verified current component effect. Blocked enables the preventive policy; PolicyDisabled writes its explicit disabled value; WindowsDefault removes the override, matching the legacy reverse. Saved restore recovers prior type/data/absence only. No player installation, playback test, license-store mutation or automatic DRM inclusion in media metadata guidance. Effective policy/source and target acceptance remain pending; normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediadrm#disableonline'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WMDRM'
      ValueName = 'DisableOnline'
      ValueType = 'DWord'
      States = @{ Blocked = 1; PolicyDisabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsMediaPolicies20261013'
      LegacySelectors = @('DisableMediaOnlineAccess', 'EnableMediaOnlineAccess')
      SettingPresentation = @{
        AppliesTo = 'Whole device; conditional Windows Media DRM backend'
        Behavior = 'EnforcedPolicy'
        GuiEffect = 'Group Policy choice for Prevent Windows Media DRM Internet Access; current component behavior is unverified'
        GuiPath = 'Computer Configuration > Windows Components > Windows Media Digital Rights Management > Prevent Windows Media DRM Internet Access'
        Requirements = @('Administrator; installed/enabled consuming WMDRM backend; current deprecation and content-service availability require independent review', 'Microsoft CSP lists Pro, Enterprise, Education and IoT Enterprise; Home and Server are not accepted here', 'No extra RIDE membership, cloud account or subscription for local configuration; payload/service/license availability is separate')
        OtherSupportedChoices = @('Blocked=1, PolicyDisabled=0 and override removal differ', 'No PlayReady or all-traffic block; no deletion of protected content or licenses', 'Registry recovery does not restore remote services, content licenses or successful playback')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediadrm#disableonline')
      }
    }
    @{
      Id = 'windows.owned-balanced-power-plan'
      Name = 'Balanced power-plan owned copy (experimental)'
      Kind = 'OwnedPowerPlan'
      Category = 'Windows settings / Power'
      Description = 'Advanced explicit creation of one separately owned Balanced template copy using exact source/destination GUIDs. Never selects it or repairs existing selection. Source availability is conditional; no name matching, fallback or adoption. Ownership intent is saved before duplication and finalized with a native export fingerprint. Recovery only deletes the same unchanged inactive owned copy after selection recovery; incomplete, changed, active or orphaned copies require review. Native export reproducibility, hardware/edition, GUI and target acceptance remain pending; normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#duplicatescheme'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'OwnedPowerPlan'
      SourcePowerPlanGuid = '381b4222-f694-41f0-9685-ff5bb260df2e'
      States = @{ Create = $true }
      TargetDefaults = @{}
      Rollback = 'Compensating'
      MigrationBatch = 'SettingsOwnedPowerPlans20261013'
      SettingPresentation = @{
        AppliesTo = 'Whole device; one separately owned power-plan copy'
        Behavior = 'Preference'
        GuiEffect = 'Creates a labeled copy for native Power Options inspection; creation does not select it'
        GuiPath = 'Control Panel > Hardware and Sound > Power Options'
        Requirements = @('Administrator and queryable exact template GUID', 'No hardware/edition fallback or implicit Ultimate Performance support', 'Restore the saved existing-plan selection before recovering an active copy; do not edit plans concurrently with recovery')
        OtherSupportedChoices = @('Existing windows.active-power-scheme selection keeps its published states and active-GUID recovery', 'No implicit reset/delete, user menu deployment or quick selection', 'Inspection reports ownership/presence; full configuration comparison occurs only during recovery')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options')
      }
    }
    @{
      Id = 'windows.owned-high-performance-power-plan'
      Name = 'High Performance power-plan owned copy (experimental)'
      Kind = 'OwnedPowerPlan'
      Category = 'Windows settings / Power'
      Description = 'Advanced explicit creation of one separately owned High Performance template copy using exact source/destination GUIDs. Never selects it or repairs existing selection. Source availability is conditional; no name matching, fallback or adoption. Ownership intent is saved before duplication and finalized with a native export fingerprint. Recovery only deletes the same unchanged inactive owned copy after selection recovery; incomplete, changed, active or orphaned copies require review. Native export reproducibility, hardware/edition, GUI and target acceptance remain pending; normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#duplicatescheme'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'OwnedPowerPlan'
      SourcePowerPlanGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
      States = @{ Create = $true }
      TargetDefaults = @{}
      Rollback = 'Compensating'
      MigrationBatch = 'SettingsOwnedPowerPlans20261013'
      SettingPresentation = @{
        AppliesTo = 'Whole device; one separately owned power-plan copy'
        Behavior = 'Preference'
        GuiEffect = 'Creates a labeled copy for native Power Options inspection; creation does not select it'
        GuiPath = 'Control Panel > Hardware and Sound > Power Options'
        Requirements = @('Administrator and queryable exact template GUID', 'No hardware/edition fallback or implicit Ultimate Performance support', 'Restore the saved existing-plan selection before recovering an active copy; do not edit plans concurrently with recovery')
        OtherSupportedChoices = @('Existing windows.active-power-scheme selection keeps its published states and active-GUID recovery', 'No implicit reset/delete, user menu deployment or quick selection', 'Inspection reports ownership/presence; full configuration comparison occurs only during recovery')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options')
      }
    }
    @{
      Id = 'windows.owned-ultimate-performance-power-plan'
      Name = 'Ultimate Performance power-plan owned copy (experimental)'
      Kind = 'OwnedPowerPlan'
      Category = 'Windows settings / Power'
      Description = 'Advanced explicit creation of one separately owned Ultimate Performance template copy using exact source/destination GUIDs. Never selects it or repairs existing selection. Source availability is conditional; no name matching, fallback or adoption. Ownership intent is saved before duplication and finalized with a native export fingerprint. Recovery only deletes the same unchanged inactive owned copy after selection recovery; incomplete, changed, active or orphaned copies require review. Native export reproducibility, hardware/edition, GUI and target acceptance remain pending; normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#duplicatescheme'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'OwnedPowerPlan'
      SourcePowerPlanGuid = 'e9a42b02-d5df-448d-aa00-03f14749eb61'
      States = @{ Create = $true }
      TargetDefaults = @{}
      Rollback = 'Compensating'
      MigrationBatch = 'SettingsOwnedPowerPlans20261013'
      SettingPresentation = @{
        AppliesTo = 'Whole device; one separately owned power-plan copy'
        Behavior = 'Preference'
        GuiEffect = 'Creates a labeled copy for native Power Options inspection; creation does not select it'
        GuiPath = 'Control Panel > Hardware and Sound > Power Options'
        Requirements = @('Administrator and queryable exact template GUID', 'No hardware/edition fallback or implicit Ultimate Performance support', 'Restore the saved existing-plan selection before recovering an active copy; do not edit plans concurrently with recovery')
        OtherSupportedChoices = @('Existing windows.active-power-scheme selection keeps its published states and active-GUID recovery', 'No implicit reset/delete, user menu deployment or quick selection', 'Inspection reports ownership/presence; full configuration comparison occurs only during recovery')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options')
      }
    }
    @{
      Id = 'windows.ceip-participation-policy'
      Name = 'Windows CEIP participation policy (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Advanced machine policy for Windows Customer Experience Improvement Program participation, separate from diagnostic-data settings and App-V CEIP. OptedOut writes 0 and corresponds to enabling the negatively named Turn off Windows CEIP policy; OptedIn writes 1 and corresponds to disabling it. WindowsDefault removes the override, matching the legacy reverse rather than explicit opt-in. Saved restore retains prior type/data/absence. This is configured local policy, not verified current collection or effective managed-policy/source. No telemetry mirrors, tasks, client activation, account/license acquisition or privacy guarantee. Implementation candidate; current consumer, precedence, GUI and target acceptance remain pending and normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-icm#ceipenable'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
      ValueName = 'CEIPEnable'
      ValueType = 'DWord'
      States = @{ OptedOut = 0; OptedIn = 1; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsWindowsCeip20261013'
      LegacySelectors = @('DisableTelemetry', 'EnableTelemetry')
      SettingPresentation = @{
        AppliesTo = 'Whole device; Windows CEIP participation policy for all users'
        Behavior = 'EnforcedPolicy'
        GuiEffect = 'Group Policy Enabled means opt-out; this is not a verified Diagnostics and feedback toggle or proof of collection suppression'
        GuiPath = 'Computer Configuration > System > Internet Communication Management > Internet Communication settings > Turn off Windows Customer Experience Improvement Program'
        Requirements = @('Administrator rights; verified policy edition/build and current Windows CEIP consumer', 'Microsoft lists Pro, Enterprise, Education and IoT Enterprise; Home and Server are not accepted here', 'No extra RIDE account, subscription, domain join or Intune enrollment for local policy configuration')
        OtherSupportedChoices = @('OptedOut=0, OptedIn=1 and override removal are distinct', 'App-V CEIP is a separate installed/enabled-client outcome, not implicitly configured', 'Native/Wow6432Node diagnostic mirrors and universal telemetry-off claims remain deferred')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-icm#ceipenable')
      }
    }
    @{
      Id = 'windows.update-notification-display-policy'
      Name = 'Windows Update notification display policy'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Updates'
      Description = 'Advanced machine policy coordinating the notification gate, display level and active-hours checkbox. DefaultNotifications requests normal notifications; KeepRestartWarnings suppresses other update notices; HideIncludingRestartWarnings is advanced suppression including restart warnings. DuringActiveHours choices constrain suppression, not the active-hours schedule. PolicyDisabled writes gate 0 and removes subordinate overrides; WindowsDefault removes all three overrides. Notifications do not prevent restarts or alter updates, deadlines or AUOptions. Read-only LegacyDebugger observation reports possible MusNotification interception without cleanup. Effective managed-policy/source, GUI/notification/reboot and payload acceptance remain pending; normal apply is blocked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#updatenotificationlevel'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11')
      PendingAcceptance = $true
      MinimumBuild = 22621
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      RegistryValues = @(
        @{ Key = 'Gate'; RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName = 'SetUpdateNotificationLevel'; ValueType = 'DWord' }
        @{ Key = 'Level'; RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName = 'UpdateNotificationLevel'; ValueType = 'DWord' }
        @{ Key = 'DuringActiveHours'; RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName = 'NoUpdateNotificationsDuringActiveHours'; ValueType = 'DWord' }
      )
      ReadOnlyRegistryValues = @(
        @{ Key = 'LegacyDebugger'; RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe'; ValueName = 'Debugger'; ValueType = 'String' }
      )
      States = @{
        DefaultNotifications = @{ Gate = 1; Level = 0; DuringActiveHours = 0 }
        KeepRestartWarnings = @{ Gate = 1; Level = 1; DuringActiveHours = 0 }
        KeepRestartWarningsDuringActiveHours = @{ Gate = 1; Level = 1; DuringActiveHours = 1 }
        HideIncludingRestartWarnings = @{ Gate = 1; Level = 2; DuringActiveHours = 0 }
        HideIncludingRestartWarningsDuringActiveHours = @{ Gate = 1; Level = 2; DuringActiveHours = 1 }
        PolicyDisabled = @{ Gate = 0; Level = $null; DuringActiveHours = $null }
        WindowsDefault = @{ Gate = $null; Level = $null; DuringActiveHours = $null }
      }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsUpdateNotifications20261013'
      SettingPresentation = @{
        AppliesTo = 'Whole device; local Windows Update notification policy'
        Behavior = 'EnforcedPolicy'
        GuiEffect = 'Configured notification policy is distinct from effective managed behavior and actual restart scheduling'
        GuiPath = 'Computer Configuration > Windows Components > Windows Update > Manage end user experience > Display options for update notifications'
        Requirements = @('Administrator rights; applicable Windows policy edition/build; no extra RIDE subscription or account', 'Active-hours checkbox requires Windows 11 22H2 build 22621 or later; all targets remain pending', 'GUI, typed payload, managed precedence and real notifications/reboots need disposable acceptance')
        OtherSupportedChoices = @('Default notifications, policy disabled and override removal are distinct local states', 'Personal Notify me when a restart is required remains a separate native user choice', 'Suppression cannot prevent updates or restarts; active hours and deadlines remain unchanged')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#updatenotificationlevel', 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#noupdatenotificationsduringactivehours', 'https://learn.microsoft.com/en-us/windows/deployment/update/waas-restart')
      }
    }
    @{
      Id = 'windows.firewall-domain-profiles'
      Name = 'Windows Firewall for Domain networks'
      Kind = 'FirewallProfile'
      Category = 'Windows settings / Security'
      Description = 'Configure only local firewall Enabled in PersistentStore for the declared network types. On enables local profile protection; Off, where offered, is advanced opt-in. Enable-all captures all three local values before its first write. Inspect configured and effective ActiveStore state, active networks and legacy policy-key presence separately. Managed policy can override local configuration. Preserve rules, app exceptions, services, logging, IPsec and traffic defaults; no policy reset, automatic legacy cleanup or local NotConfigured/default state. Saved recovery restores only captured local fields and reports profile failures. Implementation candidate: GUI, traffic and recovery VM acceptance pending.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'FirewallProfile'
      FirewallProfiles = @('Domain')
      States = @{ On = 'True'; Off = 'False' }
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsFirewallProfiles20261013'
      SettingPresentation = @{
        AppliesTo = 'Whole device; declared network types'
        Behavior = 'Configuration'
        GuiEffect = 'Local Enabled configuration is distinct from effective policy; Off is advanced and can expose active networks'
        GuiPath = 'Windows Security > Firewall and network protection > network type'
        Requirements = @('Installed NetSecurity and NetConnection cmdlets; administrator rights for writes', 'No RIDE cloud account, subscription or domain join required to configure a local profile', 'Disposable Windows 11/Server applicability, GUI and traffic acceptance remain pending')
        OtherSupportedChoices = @('Single profiles offer On and advanced Off; enable-all offers On only', 'No generic local default/reset or NotConfigured setter', 'Saved-run restore recovers prior local flags, not managed resultant policy')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile', 'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile')
      }
    }
    @{
      Id = 'windows.firewall-private-profiles'
      Name = 'Windows Firewall for Private networks'
      Kind = 'FirewallProfile'
      Category = 'Windows settings / Security'
      Description = 'Configure only local firewall Enabled in PersistentStore for the declared network types. On enables local profile protection; Off, where offered, is advanced opt-in. Enable-all captures all three local values before its first write. Inspect configured and effective ActiveStore state, active networks and legacy policy-key presence separately. Managed policy can override local configuration. Preserve rules, app exceptions, services, logging, IPsec and traffic defaults; no policy reset, automatic legacy cleanup or local NotConfigured/default state. Saved recovery restores only captured local fields and reports profile failures. Implementation candidate: GUI, traffic and recovery VM acceptance pending.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'FirewallProfile'
      FirewallProfiles = @('Private')
      States = @{ On = 'True'; Off = 'False' }
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsFirewallProfiles20261013'
      SettingPresentation = @{
        AppliesTo = 'Whole device; declared network types'
        Behavior = 'Configuration'
        GuiEffect = 'Local Enabled configuration is distinct from effective policy; Off is advanced and can expose active networks'
        GuiPath = 'Windows Security > Firewall and network protection > network type'
        Requirements = @('Installed NetSecurity and NetConnection cmdlets; administrator rights for writes', 'No RIDE cloud account, subscription or domain join required to configure a local profile', 'Disposable Windows 11/Server applicability, GUI and traffic acceptance remain pending')
        OtherSupportedChoices = @('Single profiles offer On and advanced Off; enable-all offers On only', 'No generic local default/reset or NotConfigured setter', 'Saved-run restore recovers prior local flags, not managed resultant policy')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile', 'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile')
      }
    }
    @{
      Id = 'windows.firewall-public-profiles'
      Name = 'Windows Firewall for Public networks'
      Kind = 'FirewallProfile'
      Category = 'Windows settings / Security'
      Description = 'Configure only local firewall Enabled in PersistentStore for the declared network types. On enables local profile protection; Off, where offered, is advanced opt-in. Enable-all captures all three local values before its first write. Inspect configured and effective ActiveStore state, active networks and legacy policy-key presence separately. Managed policy can override local configuration. Preserve rules, app exceptions, services, logging, IPsec and traffic defaults; no policy reset, automatic legacy cleanup or local NotConfigured/default state. Saved recovery restores only captured local fields and reports profile failures. Implementation candidate: GUI, traffic and recovery VM acceptance pending.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'FirewallProfile'
      FirewallProfiles = @('Public')
      States = @{ On = 'True'; Off = 'False' }
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsFirewallProfiles20261013'
      SettingPresentation = @{
        AppliesTo = 'Whole device; declared network types'
        Behavior = 'Configuration'
        GuiEffect = 'Local Enabled configuration is distinct from effective policy; Off is advanced and can expose active networks'
        GuiPath = 'Windows Security > Firewall and network protection > network type'
        Requirements = @('Installed NetSecurity and NetConnection cmdlets; administrator rights for writes', 'No RIDE cloud account, subscription or domain join required to configure a local profile', 'Disposable Windows 11/Server applicability, GUI and traffic acceptance remain pending')
        OtherSupportedChoices = @('Single profiles offer On and advanced Off; enable-all offers On only', 'No generic local default/reset or NotConfigured setter', 'Saved-run restore recovers prior local flags, not managed resultant policy')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile', 'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile')
      }
    }
    @{
      Id = 'windows.firewall-all-profiles'
      Name = 'Enable Windows Firewall for all network types'
      Kind = 'FirewallProfile'
      Category = 'Windows settings / Security'
      Description = 'Configure only local firewall Enabled in PersistentStore for the declared network types. On enables local profile protection; Off, where offered, is advanced opt-in. Enable-all captures all three local values before its first write. Inspect configured and effective ActiveStore state, active networks and legacy policy-key presence separately. Managed policy can override local configuration. Preserve rules, app exceptions, services, logging, IPsec and traffic defaults; no policy reset, automatic legacy cleanup or local NotConfigured/default state. Saved recovery restores only captured local fields and reports profile failures. Implementation candidate: GUI, traffic and recovery VM acceptance pending.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'FirewallProfile'
      FirewallProfiles = @('Domain', 'Private', 'Public')
      States = @{ On = 'True' }
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'SettingsFirewallProfiles20261013'
      SettingPresentation = @{
        AppliesTo = 'Whole device; declared network types'
        Behavior = 'Configuration'
        GuiEffect = 'Local Enabled configuration is distinct from effective policy; Off is advanced and can expose active networks'
        GuiPath = 'Windows Security > Firewall and network protection > network type'
        Requirements = @('Installed NetSecurity and NetConnection cmdlets; administrator rights for writes', 'No RIDE cloud account, subscription or domain join required to configure a local profile', 'Disposable Windows 11/Server applicability, GUI and traffic acceptance remain pending')
        OtherSupportedChoices = @('Single profiles offer On and advanced Off; enable-all offers On only', 'No generic local default/reset or NotConfigured setter', 'Saved-run restore recovers prior local flags, not managed resultant policy')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile', 'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile')
      }
    }
    @{
      Id = 'powershell.windows-powershell51-user-bin-path'
      Name = 'Windows PowerShell 5.1 existing user-bin startup PATH'
      Kind = 'ProfileSetting'
      Category = 'Profile settings / PowerShell'
      Description = 'Optional current-user ConsoleHost startup block: Enabled appends the existing UserProfile/bin directory to the selected shell process PATH only when no normalized equivalent is present. Other PATH entries are preserved. No immediate or persistent environment change, directory creation, tool installation, WindowsApps repair or Terminal edit. Default/unset remove only this managed block; saved-run restore recovers captured profile content. Existing processes and inherited PATH are not rewritten. Known unmarked legacy UserBinaries code requires review before enabling.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ProfileSetting'
      ProfileRuntime = 'WindowsPowerShell51'
      ProfileSetting = 'UserBinPath'
      States = @{ Enabled = 'Enabled'; Default = $null }
      BaselineState = 'Default'
      UnsetState = 'Default'
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'UserBinProfileCandidate'
      LegacySelectors = @('AddUserBinToPath')
      SettingPresentation = @{
        AppliesTo = 'Current user; installed Windows PowerShell 5.1 ConsoleHost startup'
        Behavior = 'Preference'
        GuiEffect = 'New matching local shells can find tools in an existing user bin directory. Missing directories and equivalent PATH entries cause no change. NoProfile or blocked startup bypasses the block.'
        GuiPath = 'CurrentUserCurrentHost PowerShell profile; process PATH after startup'
        Requirements = @('Selected runtime installed and profile execution permitted', 'Existing current-user bin directory; provision and review its contents separately', 'Review unmarked legacy startup writers before enabling; native Windows 11 acceptance pending')
        OtherSupportedChoices = @('Default/unset remove the block; Baseline selects Default', 'Saved-run restore recovers profile content, not environment changes in running or child processes', 'Persistent user/machine PATH, directory provisioning and WindowsApps repair remain separate')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles', 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables')
      }
    }
    @{
      Id = 'powershell.powershell7-user-bin-path'
      Name = 'PowerShell 7 existing user-bin startup PATH'
      Kind = 'ProfileSetting'
      Category = 'Profile settings / PowerShell'
      Description = 'Optional current-user ConsoleHost startup block: Enabled appends the existing UserProfile/bin directory to the selected shell process PATH only when no normalized equivalent is present. Other PATH entries are preserved. No immediate or persistent environment change, directory creation, tool installation, WindowsApps repair or Terminal edit. Default/unset remove only this managed block; saved-run restore recovers captured profile content. Existing processes and inherited PATH are not rewritten. Known unmarked legacy UserBinaries code requires review before enabling.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11')
      PendingAcceptance = $true
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'ProfileSetting'
      ProfileRuntime = 'PowerShell7'
      ProfileSetting = 'UserBinPath'
      States = @{ Enabled = 'Enabled'; Default = $null }
      BaselineState = 'Default'
      UnsetState = 'Default'
      TargetDefaults = @{}
      Rollback = 'Exact'
      MigrationBatch = 'UserBinProfileCandidate'
      LegacySelectors = @('AddUserBinToPath')
      SettingPresentation = @{
        AppliesTo = 'Current user; installed PowerShell 7 ConsoleHost startup'
        Behavior = 'Preference'
        GuiEffect = 'New matching local shells can find tools in an existing user bin directory. Missing directories and equivalent PATH entries cause no change. NoProfile or blocked startup bypasses the block.'
        GuiPath = 'CurrentUserCurrentHost PowerShell profile; process PATH after startup'
        Requirements = @('Selected runtime installed and profile execution permitted', 'Existing current-user bin directory; provision and review its contents separately', 'Review unmarked legacy startup writers before enabling; native Windows 11 acceptance pending')
        OtherSupportedChoices = @('Default/unset remove the block; Baseline selects Default', 'Saved-run restore recovers profile content, not environment changes in running or child processes', 'Persistent user/machine PATH, directory provisioning and WindowsApps repair remain separate')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles', 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables')
      }
    }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Windows Shell checks for downloaded applications'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Windows Security > App & browser control > Reputation-based protection; policy: Windows Defender SmartScreen > Explorer'
        GuiEffect = 'Disabled writes 0; Enabled writes 1. The separate warning-bypass policy and current managed precedence still govern available choices. This is not a Chromium Edge or antivirus switch.'
        Requirements = @('Existing Windows 11 declaration only; no broader target support inferred from references. RIDE does not restart, upload samples or refresh the GUI.', 'Policy mapping is documented for Windows 11 Pro, Enterprise, Education and IoT Enterprise. Network reputation availability and current GUI locking need target evidence.')
        OtherSupportedChoices = @('The legacy reverse removed EnableSmartScreen. WindowsDefault matches removal; explicit Enabled writes 1. The retired EdgeHTML PhishingFilter member remains excluded.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-smartscreen#enablesmartscreeninshell')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2100c552-7f37-4a7f-9fa0-2a864ab87212'
      SettingPresentation = @{
        AppliesTo = 'Device: Legacy StandardProfile firewall policy only'
        Behavior = 'Unverified'
        GuiPath = 'Related: Windows Security > Firewall & network protection; no verified one-to-one current profile mapping'
        GuiEffect = 'Disabled writes 0; Enabled writes 1 at StandardProfile. The current effective domain/private/public behavior is unverified for this legacy value; it is not an all-profile switch.'
        Requirements = @('Existing Windows 11 declaration only; no broader target support inferred from references. RIDE does not restart, upload samples or refresh the GUI.', 'Microsoft documents the exact legacy key/value, but current effective-profile and policy-merge evidence is still required. Rules, service state and network category are not changed.')
        OtherSupportedChoices = @('Legacy EnableFirewall removed StandardProfile/EnableFirewall; WindowsDefault matches that reverse. Use the separately modeled modern firewall profile controls for their declared scope.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2100c552-7f37-4a7f-9fa0-2a864ab87212')
      }
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
      Description = 'Configure the machine Windows Security tray-icon hiding policy. Hidden hides through policy; Shown permits display subject to intended-user startup and component readiness, rather than repairing a launcher. WindowsDefault removes the local policy override; saved restore recovers only its prior value/type/absence. Appearance requires user-controlled sign-out/sign-in or reboot. Follow docs/security-icon-startup.md for manual startup/overflow checks; those steps are not captured RIDE changes. Protection and alerts remain separate. No historical Run-command reconstruction, startup repair or forced refresh is performed.'
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
      SettingPresentation = @{
        AppliesTo = 'Whole device for hiding policy; manual startup checks in the intended interactive user context'
        Behavior = 'EnforcedPolicy'
        GuiEffect = 'Shown permits the icon but does not establish startup readiness or protection state; visible effect needs user-controlled sign-in/reboot'
        GuiPath = 'Windows Security notification area; intended-user Settings > Apps > Startup or Task Manager > Startup apps'
        Requirements = @('Administrator rights for machine policy changes; no extra RIDE account or subscription', 'Inspect startup as the intended interactive user, not an alternate administrator account', 'Existing registered native startup entry/component; missing or managed choices remain pending', 'User-controlled sign-out/sign-in or reboot for policy refresh; GUI/multi-user/Server evidence remains separate')
        OtherSupportedChoices = @('Hidden=1, Shown=0 and local override removal retain their published meanings', 'Native startup/overflow checks are manual user steps, not saved apply/restore success', 'Saved-run recovery restores the policy value only; protection, alerts and startup registration remain separate')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsdefendersecuritycenter#hidewindowssecuritynotificationareacontrol', 'https://support.microsoft.com/en-us/windows/experience/startup-boot/configure-startup-applications-in-windows')
      }
    }
    @{
      Id = 'windows.memory-integrity-request'
      Name = 'Memory integrity enablement request'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Security'
      Description = 'Write the HVCI enablement preference. Running protection still requires compatible hardware, VBS configuration, drivers and restart; this operation neither provisions those dependencies nor changes UEFI locks. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#enable-memory-integrity-using-registry'
      SettingPresentation = @{
        AppliesTo = 'Device: HVCI request in the Device Guard scenario'
        Behavior = 'Configuration'
        GuiPath = 'Windows Security > Device security > Core isolation details > Memory integrity'
        GuiEffect = 'Enabled writes 1; Disabled writes 0. This requests configuration only and does not establish running protection. GUI editability also depends on separately owned WasEnabledBy and management.'
        Requirements = @('Existing Windows 11 declaration only; no broader target support inferred from references. RIDE does not restart, upload samples or refresh the GUI.', 'Compatible virtualization/security hardware, VBS and drivers are prerequisites. Restart and active security-service verification are separate; UEFI lock, Secure Boot and boot-recovery choices are not changed.')
        OtherSupportedChoices = @('Legacy DisableCIMemoryIntegrity removed Enabled, rather than writing 0. WindowsDefault matches removal; saved recovery cannot undo driver changes, boot effects or UEFI locks.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#enable-memory-integrity-using-registry')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Microsoft Defender Antivirus sample-submission choice'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Windows Security > Virus & threat protection > Manage settings > Automatic sample submission; policy: Microsoft Defender Antivirus > MAPS'
        GuiEffect = 'Prompt=0, SafeSamples=1, Never=2 and AllSamples=3 govern the sample preference when cloud/MAPS participation applies. Restoring it cannot retract files already submitted.'
        Requirements = @('Existing Windows 11 declaration only; no broader target support inferred from references. RIDE does not restart, upload samples or refresh the GUI.', 'Operational Microsoft Defender Antivirus is required. Documented device policy applies to Pro, Enterprise, Education and IoT Enterprise; managed/tamper controls can block or override local writes. No upload or cloud contact is initiated by inspection.')
        OtherSupportedChoices = @('Legacy DisableDefenderCloud paired Never with cloud reporting off; its reverse removed both overrides. Cloud reporting remains a separate useful control; WindowsDefault restores delegation, not a guaranteed submission choice.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#submitsamplesconsent')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Legacy fixed-signature network category request'
        Behavior = 'Unverified'
        GuiPath = 'Local Security Policy > Network List Manager Policies > Unidentified Networks; legacy signature mapping unverified'
        GuiEffect = 'Private writes Category=1 at the retained fixed signature; Public writes 0. This does not select or recategorize an observed adapter.'
        Requirements = @('The Microsoft reference redirects to Windows 10 previous-version policy guidance; it does not establish this fixed signature on Windows 11. Network trust and actual firewall-profile changes need isolated acceptance.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy Public removed the value; WindowsDefault preserves that reverse, while explicit Public writes 0. No firewall rule or discovery service is owned.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-list-manager-policies#unidentified-networks')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Automatic device setup on private networks'
        Behavior = 'Unverified'
        GuiPath = 'Related Advanced sharing settings automatic setup option; current-build mapping unverified'
        GuiEffect = 'Disabled writes NcdAutoSetup/Private/AutoSetup=0; Enabled writes 1. No existing device is uninstalled or configured by this handler.'
        Requirements = @('The File Explorer reference is feature background, not this registry mapping. Current setup, device discovery and network classification remain separate acceptance.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy Enable removed the value. WindowsDefault preserves removal; explicit Enabled=1 differs. Neither state guarantees discovery or driver installation.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows')
      }
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
      Name = 'Internet Connection Sharing prohibition policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Control the machine Internet Connection Sharing prohibition policy. Published Hidden writes 0 and Available writes 1. Microsoft documents both sharing-configuration restrictions and whether the ICS service may run; this is not a UI-only preference. The handler makes no direct service call or connection configuration. WindowsDefault removes the override; exact saved recovery remains separate from native service and network acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-networkconnections#nc_showsharedaccessui'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Internet Connection Sharing configuration and service permission'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > Network > Network Connections > Prohibit use of Internet Connection Sharing on your DNS domain network'
        GuiEffect = 'The published Hidden state writes NC_ShowSharedAccessUI=0 to enable the prohibition; Available writes 1 to disable it. Microsoft describes both configuration UI and ICS service restrictions.'
        Requirements = @('Exact policy mapping is documented; installed Microsoft ADMX confirms enabled=0/disabled=1. Applicability and current managed/service behavior need acceptance. The handler makes no direct SharedAccess stop/start call.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy Enable removed the value. WindowsDefault preserves removal; Available=1 is explicit policy-disabled. Availability does not configure sharing; reviewed connectivity prerequisites remain necessary.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-networkconnections#nc_showsharedaccessui')
      }
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
      Description = 'Show or hide the advanced legacy Sleep menu preference. Available sleep states and policy still govern whether it appears. The reference documents the separate ShowSleepOption policy, not this FlyoutMenuSettings registry mapping. Dedicated sleep-button actions are separate operations. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer#showsleepoption'
      SettingPresentation = @{
        AppliesTo = 'All users on this device: advanced legacy Sleep menu visibility preference'
        Behavior = 'Preference'
        GuiPath = 'Related controls: Control Panel > Hardware and Sound > Power Options > Choose what the power buttons do > Shutdown settings > Sleep; Start > Power'
        GuiEffect = 'Hidden writes 0 and Shown writes 1 to the FlyoutMenuSettings preference. WindowsDefault, Baseline and unset remove this override. Current checkbox/menu mapping and policy precedence remain unverified; showing the entry cannot create sleep support or change a hardware button.'
        Requirements = @('Administrator privileges and hardware-supported sleep. Microsoft documents the separate policy under Software/Policies/Microsoft/Windows/Explorer; it does not document this migrated FlyoutMenuSettings mapping.', 'Keep this advanced preference outside recommended compositions pending current GUI/managed/refresh evidence. No Explorer restart or capability change is performed.')
        OtherSupportedChoices = @('The separate enforced Show sleep in the power options menu policy is not implemented by this ID. Power-button/lid actions, the dedicated sleep button and idle timers remain independent.', 'Legacy EnableSleepButton explicitly showed the menu and set both dedicated-button indexes to Sleep. WindowsDefault removes only this preference; saved restore recovers its captured value/type/absence.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer#showsleepoption', 'https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-sleep-button-action')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Window movement rendering'
        Behavior = 'Preference'
        GuiPath = 'Performance Options > Visual Effects > Show window contents while dragging'
        GuiEffect = 'Contents writes DragFullWindows string 1; Outline writes 0. The intended choice is full content versus an outline during window movement.'
        Requirements = @('The API documents drag rendering, not this direct registry-write contract. Session caching and application behavior require native verification.', 'Existing Windows 11 declaration retained; no new target, native acceptance, session refresh, restart or sign-out.')
        OtherSupportedChoices = @('Legacy Performance and Appearance wrote the offered explicit values. WindowsDefault, Baseline and unset instead remove this override. Saved restore recovers the captured value/type/absence. The broader legacy bundle also changed keyboard delay and packed UserPreferencesMask/VisualFXSetting; no complete bundle equivalence is claimed.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Delay before opening cascading menus'
        Behavior = 'Preference'
        GuiPath = 'No verified dedicated Settings control for the two offered delay values'
        GuiEffect = 'Immediate writes MenuShowDelay string 0; Delay400ms writes 400. The intended delay is for cascading menu appearance, not animation duration or all application menus.'
        Requirements = @('The API describes menu delay in milliseconds; it does not establish this direct registry mapping. The 400ms state is a legacy explicit choice, not a measured platform default.', 'Existing Windows 11 declaration retained; no new target, native acceptance, session refresh, restart or sign-out.')
        OtherSupportedChoices = @('Legacy Performance and Appearance wrote the offered explicit values. WindowsDefault, Baseline and unset instead remove this override. Saved restore recovers the captured value/type/absence. The broader legacy bundle also changed keyboard delay and packed UserPreferencesMask/VisualFXSetting; no complete bundle equivalence is claimed.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-animationinfo'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Window minimization and restoration animation'
        Behavior = 'Preference'
        GuiPath = 'Performance Options > Visual Effects > Animate windows when minimizing and maximizing; current mapping requires acceptance'
        GuiEffect = 'Enabled writes MinAnimate string 1; Disabled writes 0. This request owns only the retained window-animation preference.'
        Requirements = @('Microsoft documents the ANIMATIONINFO minimize/restore behavior, not MinAnimate registry writes. Application-specific rendering and session refresh remain unverified.', 'Existing Windows 11 declaration retained; no new target, native acceptance, session refresh, restart or sign-out.')
        OtherSupportedChoices = @('Legacy Performance and Appearance wrote the offered explicit values. WindowsDefault, Baseline and unset instead remove this override. Saved restore recovers the captured value/type/absence. The broader legacy bundle also changed keyboard delay and packed UserPreferencesMask/VisualFXSetting; no complete bundle equivalence is claimed.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-animationinfo')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: stored keyboard repeat delay'
        Behavior = 'Preference'
        GuiPath = 'Control Panel > Keyboard > Speed > Repeat delay (related UI; current mapping needs acceptance)'
        GuiEffect = 'Shortest, LegacyAppearance, Position2 and Longest store positions 0, 1, 2 and 3. WindowsDefault removes the stored override; this registry-only handler does not refresh the interactive session or read its effective delay.'
        Requirements = @(
          'Windows 11 intended user; no administrator rights required. Actual delay depends on hardware; repeat speed is a separate preference',
          'Microsoft documents the API range, not this registry mapping. GUI, sign-in persistence and actual key-repeat behavior remain pending'
        )
        OtherSupportedChoices = @(
          'Baseline and unset remove this override; image-dependent literal and effective defaults remain unknown, not a promised slider position',
          'Saved-run restore recovers the original value, type and absence; LegacyAppearance is the retained position-1 alias, not a complete visual-effects preset'
        )
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow')
      }
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Choose stored keyboard repeat-delay position 0 (Shortest), 1 (LegacyAppearance), 2 (Position2) or 3 (Longest), not repeat speed. Intermediate timing is hardware dependent. Uses the existing String registry preference; the Microsoft API reference documents the 0-3 feature range, not this registry mapping. Stored state is not effective interactive-session readback. WindowsDefault removes the override; saved-run restore retains original value/type/absence, including legacy DWORD and unexpected representations. No native setter, change notification or refresh is performed. GUI/persistence/actual-delay acceptance and a versioned native backend remain pending; no Server support is added.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Control Panel\Keyboard'
      ValueName = 'KeyboardDelay'
      ValueType = 'String'
      States = @{ 'Shortest' = '0'; 'LegacyAppearance' = '1'; 'Position2' = '2'; 'Longest' = '3'; 'WindowsDefault' = $null }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy Explorer selection-rectangle rendering request'
        Behavior = 'Unverified'
        GuiPath = 'Related Performance Options choice: Show translucent selection rectangle; current registry mapping requires acceptance'
        GuiEffect = 'Enabled writes ListviewAlphaSelect DWORD 1; Disabled writes 0. Current Explorer rendering is unverified; this does not select files, toggle item checkboxes or change system-wide transparency.'
        Requirements = @('The API reference is background for visual preferences and does not document ListviewAlphaSelect. Verify selection feedback on the actual Explorer and desktop surfaces.', 'Existing Windows 11 declaration retained; no new target, native acceptance, session refresh, restart or sign-out.')
        OtherSupportedChoices = @('Legacy Performance and Appearance wrote the offered explicit values. WindowsDefault, Baseline and unset instead remove this override. Saved restore recovers the captured value/type/absence. The broader legacy bundle also changed keyboard delay and packed UserPreferencesMask/VisualFXSetting; no complete bundle equivalence is claimed.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy desktop icon-label shadow request'
        Behavior = 'Unverified'
        GuiPath = 'Related Performance Options choice: Use drop shadows for icon labels on the desktop; current registry mapping requires acceptance'
        GuiEffect = 'Enabled writes ListviewShadow DWORD 1; Disabled writes 0. Current label rendering is unverified. Icon visibility, wallpaper and file contents are independent.'
        Requirements = @('The API reference does not document ListviewShadow. Theme, contrast, background and shell behavior require current-build acceptance.', 'Existing Windows 11 declaration retained; no new target, native acceptance, session refresh, restart or sign-out.')
        OtherSupportedChoices = @('Legacy Performance and Appearance wrote the offered explicit values. WindowsDefault, Baseline and unset instead remove this override. Saved restore recovers the captured value/type/absence. The broader legacy bundle also changed keyboard delay and packed UserPreferencesMask/VisualFXSetting; no complete bundle equivalence is claimed.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow')
      }
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
      Name = 'Desktop Peek legacy preference (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / UI'
      Description = 'Set the legacy desktop-composition Peek preference. Does not implement every taskbar preview or enable DWM. The Microsoft reference explains composition, not this retained value; current Windows 11 effect needs UI verification. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/dwm/dwm-overview'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy Desktop Window Manager Peek request'
        Behavior = 'Unverified'
        GuiPath = 'No verified current Windows 11 GUI mapping for EnableAeroPeek'
        GuiEffect = 'Enabled writes EnableAeroPeek DWORD 1; Disabled writes 0. This retained legacy request does not establish desktop preview, thumbnail preview or current taskbar behavior.'
        Requirements = @('Microsoft describes DWM composition, not this registry mapping. Windows 10 Peek documentation must not be treated as Windows 11 acceptance. DWM availability alone proves no effect.', 'Existing Windows 11 declaration retained; no new target, native acceptance, session refresh, restart or sign-out.')
        OtherSupportedChoices = @('Legacy Performance and Appearance wrote the offered explicit values. WindowsDefault, Baseline and unset instead remove this override. Saved restore recovers the captured value/type/absence. The broader legacy bundle also changed keyboard delay and packed UserPreferencesMask/VisualFXSetting; no complete bundle equivalence is claimed.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/dwm/dwm-overview')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Network namespace enumeration in Explorer'
        Behavior = 'Unverified'
        GuiPath = 'File Explorer navigation and shell views; no verified GUI control for NonEnum'
        GuiEffect = 'Hidden writes the Network CLSID NonEnum value as 1; Visible writes 0. It does not disable adapters, network access or discovery.'
        Requirements = @('Microsoft documents shell namespace placement, not this NonEnum mapping. Explorer and file-dialog rendering need current-build acceptance.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy Show removed the value; WindowsDefault preserves removal. Explicit Visible=0 differs. Recovery owns the registry value, not discovered devices or connection state.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: OneDrive file storage and synchronization'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > Windows Components > OneDrive > Prevent the usage of OneDrive for file storage'
        GuiEffect = 'Blocked writes DisableFileSyncNGSC=1; Allowed writes 0. Blocking can restrict OneDrive access in apps and Explorer as well as synchronization.'
        Requirements = @('Microsoft documents the mapping. Client version, tenant policy and policy refresh affect effective behavior; preserve synchronized and unsynchronized user data.', 'Retain current target declarations. No application launch, package installation, sign-out or policy refresh is explicitly invoked.')
        OtherSupportedChoices = @('Legacy EnableOneDrive removed the value. WindowsDefault retains removal; explicit Allowed=0 differs. No uninstall or file deletion is requested.', 'Saved-run restore recovers registry type/value/absence, not application or cloud data and not every secondary OS effect. Baseline application remains separate.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#disableonedrivefilesync')
      }
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
      Description = 'Control first-sign-in animation and the Microsoft-account service opt-in prompt through a machine policy. Disabled writes 0; Enabled writes 1. The legacy Enable selector removed the override instead; WindowsDefault preserves that removal. Existing sessions are unaffected and Server has no animation. Exact prior-value recovery is separate from new-user behavior acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#enablefirstlogonanimation'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Machine policy for a user first signing in'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > System > Logon > Show first sign-in animation'
        GuiEffect = 'Disabled writes EnableFirstLogonAnimation=0 and suppresses the first-sign-in animation and Microsoft-account service opt-in prompt; Enabled writes 1. Existing sessions are unaffected.'
        Requirements = @('Microsoft documents this exact policy path. Policy applicability and effective precedence need verification; the animation is not shown on Server. No account is created or signed in.', 'Existing Windows 11 declaration retained; no new target, native acceptance, session refresh, restart or sign-out.')
        OtherSupportedChoices = @('Legacy Enable removed the value. WindowsDefault, Baseline and unset retain removal; explicit Enabled is distinct. Unconfigured behavior differs for the initial setup user and later new users. Saved restore recovers the captured value/type/absence.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#enablefirstlogonanimation')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Windows Media Player Legacy library sharing'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > Windows Components > Windows Media Player > Prevent Media Sharing'
        GuiEffect = 'Blocked writes PreventLibrarySharing=1. UserChoice writes 0, permitting user control without starting sharing.'
        Requirements = @('Requires the applicable legacy Player component; modern Media Player and unrelated streaming apps are separate. Microsoft documents this policy mapping.', 'Retain current target declarations. No application launch, package installation, sign-out or policy refresh is explicitly invoked.')
        OtherSupportedChoices = @('Legacy EnableMediaSharing removed the value. WindowsDefault retains removal; UserChoice=0 is explicit.', 'Saved-run restore recovers registry type/value/absence, not application or cloud data and not every secondary OS effect. Baseline application remains separate.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventlibrarysharing')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Windows Media Player Legacy CD/DVD metadata'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Windows Media Player Legacy > Options > Privacy; related first-use media-information option'
        GuiEffect = 'Blocked writes PreventCDDVDMetadataRetrieval=1 and locks the related retrieval option off. UserChoice writes 0 and allows user choice.'
        Requirements = @('Requires the applicable legacy Player; current retrieval-service availability is not established by the policy.', 'Retain current target declarations. No application launch, package installation, sign-out or policy refresh is explicitly invoked.')
        OtherSupportedChoices = @('Legacy EnableMediaOnlineAccess removed this value. WindowsDefault matches removal; UserChoice=0 differs. Music, radio and WMDRM were separate parts of the same bundle.', 'Saved-run restore recovers registry type/value/absence, not application or cloud data and not every secondary OS effect. Baseline application remains separate.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventcddvdmetadataretrieval')
      }
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
      Description = 'Prevent internet retrieval of music-file media information in Windows Media Player Legacy. Separate from CD/DVD metadata. Radio presets and WMDRM online controls are separate experimental candidates with unverified current component effects; they are excluded from automatic metadata guidance. WindowsDefault removes this override; saved-run restore recovers the prior value and type. No restart or application refresh is performed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventmusicfilemetadataretrieval'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Windows Media Player Legacy music-file metadata'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Windows Media Player Legacy > Options > Privacy / Media Library'
        GuiEffect = 'Blocked writes PreventMusicFileMetadataRetrieval=1 and locks the related metadata option off. UserChoice writes 0 and allows user choice.'
        Requirements = @('Requires the applicable legacy Player. This does not block every codec or other media network request.', 'Retain current target declarations. No application launch, package installation, sign-out or policy refresh is explicitly invoked.')
        OtherSupportedChoices = @('Legacy EnableMediaOnlineAccess removed this value. WindowsDefault matches removal; UserChoice=0 differs. Radio and WMDRM candidates retain separate experimental acceptance.', 'Saved-run restore recovers registry type/value/absence, not application or cloud data and not every secondary OS effect. Baseline application remains separate.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventmusicfilemetadataretrieval')
      }
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
      Description = 'Set only AppModelUnlock AllowDevelopmentWithoutDevLicense: Enabled=1, Disabled=0, WindowsDefault removes it. Microsoft documents this value for registering development app packages from folders. This operation does not explicitly provision feature packages, configure Device Portal or SSH, or manage certificates. Windows may react to the preference; full Developer Mode UI behavior and cleanup require separate acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/dev-tools/winapp-cli/security#what-enabling-it-changes'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Local unpackaged app development permission'
        Behavior = 'Configuration'
        GuiPath = 'Windows 11 25H2+: Settings > System > Advanced > For developers; earlier builds: For developers page'
        GuiEffect = 'Enabled writes AllowDevelopmentWithoutDevLicense=1; Disabled writes 0; WindowsDefault removes the override. The full Developer Mode UI can manage additional OS state.'
        Requirements = @('Microsoft documents registration of unpackaged development apps through this value. Companion sideloading, managed policy, feature packages, Device Portal and SSH remain separate; verify resulting OS behavior.', 'Retain current target declarations. No application launch, package installation, sign-out or policy refresh is explicitly invoked.')
        OtherSupportedChoices = @('Legacy EnableDeveloperMode wrote both development and sideload values as 1; Disable removed both. Current Disabled=0 differs; WindowsDefault matches removal.', 'Saved-run restore recovers registry type/value/absence, not application or cloud data and not every secondary OS effect. Baseline application remains separate.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/dev-tools/winapp-cli/security#what-enabling-it-changes', 'https://learn.microsoft.com/en-us/windows/advanced-settings/developer-mode')
      }
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
      Description = 'Set only AppModelUnlock AllowAllTrustedApps: Enabled=1, Disabled=0, WindowsDefault removes it. Microsoft documents this local value for installing trusted signed app packages outside the Store. It does not add certificate trust, install apps, or reproduce the complete Developer Mode workflow; current managed-policy and GUI behavior require acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/dev-tools/winapp-cli/security#what-enabling-it-changes'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Local trusted app sideload permission'
        Behavior = 'Configuration'
        GuiPath = 'Related Developer Mode settings; no independently verified current GUI switch for this value'
        GuiEffect = 'Enabled writes AllowAllTrustedApps=1; Disabled writes 0; WindowsDefault removes it. This permits trusted signed app packages outside the Store subject to other controls.'
        Requirements = @('Microsoft documents this exact local value. Certificate trust and app deployment remain separate; no certificate or package is installed by this registry operation.', 'Retain current target declarations. No application launch, package installation, sign-out or policy refresh is explicitly invoked.')
        OtherSupportedChoices = @('Legacy EnableDeveloperMode wrote both values as 1 and Disable removed both. WindowsDefault matches removal; Disabled=0 is explicit.', 'Saved-run restore recovers registry type/value/absence, not application or cloud data and not every secondary OS effect. Baseline application remains separate.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/dev-tools/winapp-cli/security#what-enabling-it-changes', 'https://learn.microsoft.com/en-us/windows/advanced-settings/developer-mode')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy Game Mode preference'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Settings > Gaming > Game Mode; exact registry mapping unverified'
        GuiEffect = 'Disabled writes AutoGameModeEnabled=0; Enabled writes 1; WindowsDefault removes it. Current GUI and performance effects are unverified.'
        Requirements = @('The Microsoft feature reference does not document this value. Game Mode, Game Bar recording and newer Xbox mode are distinct; keep the experimental mapping out of recommendations pending current-build evidence.', 'Retain current target declarations. No application launch, package installation, sign-out or policy refresh is explicitly invoked.')
        OtherSupportedChoices = @('Legacy EnableXboxFeatures removed this value. WindowsDefault matches removal; Enabled=1 differs. Xbox app removal/registration remains separate.', 'Saved-run restore recovers registry type/value/absence, not application or cloud data and not every secondary OS effect. Baseline application remains separate.')
        ReferenceUris = @('https://support.microsoft.com/en-us/accessibility/windows/understand-and-explore-windows-settings')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy per-user Game Bar recording preference'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Settings > Gaming > Captures; exact current mapping unverified'
        GuiEffect = 'Disabled writes GameDVR_Enabled=0; Enabled writes 1; WindowsDefault removes it. Machine recording policy remains independent.'
        Requirements = @('The current reference describes machine policy, not this user value. Game Bar version, hardware and other controls require native evaluation.', 'Retain current target declarations. No application launch, package installation, sign-out or policy refresh is explicitly invoked.')
        OtherSupportedChoices = @('Legacy Disable/EnableXboxFeatures wrote this user value as 0/1, matching the numeric pair, but also changed policy and app registration. Those bundle effects are not included.', 'Saved-run restore recovers registry type/value/absence, not application or cloud data and not every secondary OS effect. Baseline application remains separate.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationmanagement#allowgamedvr')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Legacy machine Game Recording and Broadcasting policy'
        Behavior = 'Unverified'
        GuiPath = 'Computer Configuration > Administrative Templates > Windows Components > Windows Game Recording and Broadcasting'
        GuiEffect = 'Disabled writes AllowGameDVR=0; Allowed writes 1; WindowsDefault removes it. Enforcement on the declared Windows 11 target remains unverified.'
        Requirements = @('Microsoft documents the exact mapping but expressly limits enforcement to Windows 10 desktop. Retain the experimental Windows 11 qualification; do not infer current enforcement from registry success.', 'Retain current target declarations. No application launch, package installation, sign-out or policy refresh is explicitly invoked.')
        OtherSupportedChoices = @('Legacy EnableXboxFeatures removed this policy. WindowsDefault matches removal; Allowed=1 differs. User recording preference and app registration remain separate.', 'Saved-run restore recovers registry type/value/absence, not application or cloud data and not every secondary OS effect. Baseline application remains separate.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationmanagement#allowgamedvr')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy taskbar-animation request'
        Behavior = 'Unverified'
        GuiPath = 'Related Performance Options choice: Animations in the taskbar; current Windows 11 effect unverified'
        GuiEffect = 'Enabled writes TaskbarAnimations DWORD 1; Disabled writes 0. The Windows 11 taskbar may ignore it; neither state promises all taskbar animation will change.'
        Requirements = @('The API reference does not document this value. Accessibility animation preferences and application effects are separate; verify the chosen target and shell build.', 'Existing Windows 11 declaration retained; no new target, native acceptance, session refresh, restart or sign-out.')
        OtherSupportedChoices = @('Legacy Performance and Appearance wrote the offered explicit values. WindowsDefault, Baseline and unset instead remove this override. Saved restore recovers the captured value/type/absence. The broader legacy bundle also changed keyboard delay and packed UserPreferencesMask/VisualFXSetting; no complete bundle equivalence is claimed.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine service DiagTrack; elevation required'
        Behavior = 'Configuration'
        GuiPath = 'Services (services.msc) > DiagTrack > Properties > General; startup type and service status are separate'
        GuiEffect = 'Disabled sets Disabled startup and stops DiagTrack; AutomaticRunning selects Automatic and starts or resumes it, preserving the existing delayed-start flag.'
        Requirements = @('The Microsoft service overview describes Server 2016 behavior; it is not Windows 11 default or privacy acceptance. Other diagnostic policies and traffic sources remain separate.', 'Service must exist; dependencies, managed policy and transient states can prevent transitions. Existing supported targets are unchanged; no new GUI, boot or workload acceptance is claimed.')
        OtherSupportedChoices = @('Legacy DisableDiagTrack/EnableDiagTrack selected the same stop/disable and automatic/start intent. No zero-telemetry guarantee follows from a stopped service.', 'There is no unset/override-removal state. Restore the saved run for prior startup/runtime; an explicit preset or RIDE baseline is not a Windows default. Recovery does not undo effects in workloads or unowned dependencies.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server')
      }
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
      Description = 'Advanced opt-in service control. AutomaticRunning sets Automatic and starts now while preserving delay; Disabled stops and disables while preserving the dormant delay. AutomaticDelayedRunning selects Automatic (Delayed Start) and starts now. Startup-only AutomaticStartup, AutomaticDelayedStartup, ManualStartup and DisabledStartup preserve runtime. Boot scheduling applies next boot with no fixed delay guarantee. Device-management workloads may depend on this service. Baseline AutomaticRunning is a RIDE choice, not a Windows default. Saved restore captures startup/runtime, SCM delay and literal delay value/type/absence. Missing services and failed stages are explicit. New choices await GUI/SCM/boot/workload VM acceptance; no Server support is added.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info'
      SettingPresentation = @{
        AppliesTo = 'Machine service dmwappushservice; elevation required'
        Behavior = 'Configuration'
        GuiPath = 'Services (services.msc) > dmwappushservice > Properties > General; startup type and service status are separate'
        GuiEffect = 'AutomaticRunning starts now and preserves delay; Disabled stops and disables. AutomaticDelayedRunning sets delay and starts now. Startup-only states preserve current runtime; delayed scheduling applies at a later boot.'
        Requirements = @('Review management dependencies before changes. Microsoft documents Intune sync failure when this service is disabled on Windows 10; current Windows 11 enrollment/workload acceptance remains separate.', 'Service must exist; dependencies, managed policy and transient states can prevent transitions. Existing supported targets are unchanged; no new GUI, boot or workload acceptance is claimed.')
        OtherSupportedChoices = @('Legacy EnableWAPPush explicitly set DelayedAutoStart=1 and started the service. AutomaticDelayedRunning represents that intent; AutomaticRunning preserves existing delay and is not an exact legacy reverse.', 'There is no unset/override-removal state. Restore the saved run for prior startup/runtime; an explicit preset or RIDE baseline is not a Windows default. Recovery does not undo effects in workloads or unowned dependencies.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info', 'https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-management/cannot-sync-windows-10-devices')
      }
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'WindowsService'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PreserveDelayedAutoStart = $true
      ServiceName = 'dmwappushservice'
      States = @{
        'Disabled' = @{ StartupType = 'Disabled'; Status = 'Stopped' }
        'AutomaticRunning' = @{ StartupType = 'Automatic'; Status = 'Running' }
        'AutomaticDelayedRunning' = @{ StartupType = 'Automatic'; Status = 'Running'; DelayedAutoStart = $true }
        'AutomaticStartup' = @{ StartupType = 'Automatic'; DelayedAutoStart = $false }
        'AutomaticDelayedStartup' = @{ StartupType = 'Automatic'; DelayedAutoStart = $true }
        'ManualStartup' = @{ StartupType = 'Manual' }
        'DisabledStartup' = @{ StartupType = 'Disabled' }
      }
      BaselineState = 'AutomaticRunning'
      MigrationBatch = '2026-10-10-settings60'
      LegacySelectors = @('DisableWAPPush', 'EnableWAPPush')
    }
    @{
      Id = 'windows.sysmain-service'
      Name = 'SysMain service (historically Superfetch)'
      Kind = 'WindowsService'
      Category = 'Windows settings / Services'
      Description = 'Disabled stops the service and sets Disabled startup. AutomaticRunning sets Automatic and starts it. The historical Superfetch selector controls SysMain; this does not clear prefetch data. Baseline AutomaticRunning is an explicit RIDE choice. Capture and restore startup mode and running state; a missing service is an error rather than an invented default.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
      SettingPresentation = @{
        AppliesTo = 'Machine service SysMain; elevation required'
        Behavior = 'Configuration'
        GuiPath = 'Services (services.msc) > SysMain > Properties > General; startup type and service status are separate'
        GuiEffect = 'Disabled selects Disabled startup and stops SysMain; AutomaticRunning selects Automatic and starts or resumes it, preserving captured delayed-start configuration.'
        Requirements = @('Review workload effects on the selected Windows build. The Microsoft Server 2016 service overview does not establish Windows 11 defaults or a universal performance recommendation.', 'Service must exist; dependencies, managed policy and transient states can prevent transitions. Existing supported targets are unchanged; no new GUI, boot or workload acceptance is claimed.')
        OtherSupportedChoices = @('Legacy DisableSuperfetch/EnableSuperfetch used the same stop/disable and automatic/start intent. Neither direction clears caches or proves a performance improvement.', 'There is no unset/override-removal state. Restore the saved run for prior startup/runtime; an explicit preset or RIDE baseline is not a Windows default. Recovery does not undo effects in workloads or unowned dependencies.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server')
      }
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
      Description = 'Advanced opt-in service control. AutomaticRunning sets Automatic and starts now while preserving delay; Disabled stops and disables while preserving the dormant delay. AutomaticDelayedRunning selects Automatic (Delayed Start) and starts now. Startup-only AutomaticStartup, AutomaticDelayedStartup, ManualStartup and DisabledStartup preserve runtime. Boot scheduling applies next boot with no fixed delay guarantee. Disabling can impair indexed search; no index files are deleted. Baseline AutomaticRunning is a RIDE choice, not a Windows default. Saved restore captures startup/runtime, SCM delay and literal delay value/type/absence. Missing services and failed stages are explicit. New choices await GUI/SCM/boot/workload VM acceptance; no Server support is added.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info'
      SettingPresentation = @{
        AppliesTo = 'Machine service WSearch; elevation required'
        Behavior = 'Configuration'
        GuiPath = 'Services (services.msc) > WSearch > Properties > General; startup type and service status are separate'
        GuiEffect = 'AutomaticRunning starts now and preserves delay; Disabled stops and disables indexing service operation. AutomaticDelayedRunning sets delay and starts now; startup-only choices preserve runtime.'
        Requirements = @('Indexed search consumers require separate workload verification. No index deletion, search-location change or automatic index rebuild is requested. Explicit start does not wait for delayed boot scheduling.', 'Service must exist; dependencies, managed policy and transient states can prevent transitions. Existing supported targets are unchanged; no new GUI, boot or workload acceptance is claimed.')
        OtherSupportedChoices = @('Legacy EnableIndexing set DelayedAutoStart=1 before starting. AutomaticDelayedRunning represents that intent; AutomaticRunning preserves existing delay. No guarantee of completed indexing follows from Running.', 'There is no unset/override-removal state. Restore the saved run for prior startup/runtime; an explicit preset or RIDE baseline is not a Windows default. Recovery does not undo effects in workloads or unowned dependencies.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info')
      }
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'WindowsService'
      TargetDefaults = @{ 'Windows 11' = @{ 'DefaultValue' = 'PlatformDefined'; 'EffectiveDefault' = 'Image, edition and platform configuration determine the initial state; the RIDE baseline is not a claim about the Windows default' } }
      Rollback = 'Exact'
      PreserveDelayedAutoStart = $true
      ServiceName = 'WSearch'
      States = @{
        'Disabled' = @{ StartupType = 'Disabled'; Status = 'Stopped' }
        'AutomaticRunning' = @{ StartupType = 'Automatic'; Status = 'Running' }
        'AutomaticDelayedRunning' = @{ StartupType = 'Automatic'; Status = 'Running'; DelayedAutoStart = $true }
        'AutomaticStartup' = @{ StartupType = 'Automatic'; DelayedAutoStart = $false }
        'AutomaticDelayedStartup' = @{ StartupType = 'Automatic'; DelayedAutoStart = $true }
        'ManualStartup' = @{ StartupType = 'Manual' }
        'DisabledStartup' = @{ StartupType = 'Disabled' }
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device active power plan: dedicated sleep button, When plugged in (AC)'
        Behavior = 'Configuration'
        GuiPath = 'Control Panel > Hardware and Sound > Power Options > Choose what the power buttons do; dedicated sleep-button choice appears only where exposed by the platform'
        GuiEffect = 'DoNothing writes index 0 and Sleep writes 1 for When plugged in (AC). This configures a future dedicated sleep-button press, not the power button, lid or Start menu. Available sleep states and policy still govern behavior; a stored index is not proof of suspend/resume.'
        Requirements = @('Administrator privileges for this machine-scoped handler, an available setting in the active plan and applicable hardware. Missing indexes remain Unavailable; no capability or hibernation is enabled.', 'The handler commits the changed index by reactivating the same plan. It does not intentionally switch to a different plan. Managed policy, GUI editability, plan-switch races and physical-button behavior require separate acceptance.')
        OtherSupportedChoices = @('Microsoft also defines Hibernate and Shut Down for the dedicated button. Those choices are not yet exposed by this ID; capability checks and target acceptance must precede additional states.', 'No baseline/unset is declared. Saved restore writes the exact captured index to its captured plan, committing only if that plan is still active; it does not switch back from another selected plan. The other power-source index is independent.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-sleep-button-action', 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/display--sleep--and-hibernate-idle-timers')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device active power plan: dedicated sleep button, On battery (DC)'
        Behavior = 'Configuration'
        GuiPath = 'Control Panel > Hardware and Sound > Power Options > Choose what the power buttons do; dedicated sleep-button choice appears only where exposed by the platform'
        GuiEffect = 'DoNothing writes index 0 and Sleep writes 1 for On battery (DC). This configures a future dedicated sleep-button press, not the power button, lid or Start menu. Available sleep states and policy still govern behavior; a stored index is not proof of suspend/resume.'
        Requirements = @('Administrator privileges for this machine-scoped handler, an available setting in the active plan and applicable hardware. Missing indexes remain Unavailable; no capability or hibernation is enabled.', 'The handler commits the changed index by reactivating the same plan. It does not intentionally switch to a different plan. Managed policy, GUI editability, plan-switch races and physical-button behavior require separate acceptance.')
        OtherSupportedChoices = @('Microsoft also defines Hibernate and Shut Down for the dedicated button. Those choices are not yet exposed by this ID; capability checks and target acceptance must precede additional states.', 'No baseline/unset is declared. Saved restore writes the exact captured index to its captured plan, committing only if that plan is still active; it does not switch back from another selected plan. The other power-source index is independent.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-sleep-button-action', 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/display--sleep--and-hibernate-idle-timers')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device active power plan: screen-off timer, When plugged in (AC)'
        Behavior = 'Configuration'
        GuiPath = 'Settings > System > Power & battery (or Power) > Screen, sleep, & hibernate timeouts > When plugged in (AC) > Turn my screen off after; wording and availability vary by build/platform'
        GuiEffect = 'Never writes 0 seconds; TenMinutes writes 600 seconds (10 minutes) for When plugged in (AC). Screen-off does not itself suspend the device or change screen-saver/sign-in settings. The other timer and power-source index remain independent.'
        Requirements = @('Administrator privileges, an available index in the active power plan and applicable hardware. Policy, power requests and platform capabilities affect the actual transition; a saved value alone proves no screen-off or suspend/resume.', 'Traditional sleep and Modern Standby interpret idle transitions differently. Battery presence, AC/DC conditions and effective GUI/managed behavior need target evidence. No reboot, immediate sleep or hibernation provisioning is performed.')
        OtherSupportedChoices = @('Native settings offer other durations. This ID currently exposes Never and the one legacy 10-minute preset; neither is a universal Windows default. Custom/extra durations remain implementation work.', 'No baseline/unset is declared. Saved restore preserves the exact captured index in the captured plan; it does not round to a named preset or restore a factory plan. The handler reactivates the same plan on apply and does not switch plans during restore.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/display-settings-display-idle-timeout', 'https://support.microsoft.com/en-us/windows/experience/power-battery/power-settings-in-windows-11', 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/display--sleep--and-hibernate-idle-timers')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device active power plan: screen-off timer, On battery (DC)'
        Behavior = 'Configuration'
        GuiPath = 'Settings > System > Power & battery (or Power) > Screen, sleep, & hibernate timeouts > On battery (DC) > Turn my screen off after; wording and availability vary by build/platform'
        GuiEffect = 'Never writes 0 seconds; FiveMinutes writes 300 seconds (5 minutes) for On battery (DC). Screen-off does not itself suspend the device or change screen-saver/sign-in settings. The other timer and power-source index remain independent.'
        Requirements = @('Administrator privileges, an available index in the active power plan and applicable hardware. Policy, power requests and platform capabilities affect the actual transition; a saved value alone proves no screen-off or suspend/resume.', 'Traditional sleep and Modern Standby interpret idle transitions differently. Battery presence, AC/DC conditions and effective GUI/managed behavior need target evidence. No reboot, immediate sleep or hibernation provisioning is performed.')
        OtherSupportedChoices = @('Native settings offer other durations. This ID currently exposes Never and the one legacy 5-minute preset; neither is a universal Windows default. Custom/extra durations remain implementation work.', 'No baseline/unset is declared. Saved restore preserves the exact captured index in the captured plan; it does not round to a named preset or restore a factory plan. The handler reactivates the same plan on apply and does not switch plans during restore.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/display-settings-display-idle-timeout', 'https://support.microsoft.com/en-us/windows/experience/power-battery/power-settings-in-windows-11', 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/display--sleep--and-hibernate-idle-timers')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device active power plan: idle sleep timer, When plugged in (AC)'
        Behavior = 'Configuration'
        GuiPath = 'Settings > System > Power & battery (or Power) > Screen, sleep, & hibernate timeouts > When plugged in (AC) > Make my device sleep after; wording and availability vary by build/platform'
        GuiEffect = 'Never writes 0 seconds; ThirtyMinutes writes 1800 seconds (30 minutes) for When plugged in (AC). Never disables this idle-sleep timer, not manual/button/lid sleep or every other power transition. The other timer and power-source index remain independent.'
        Requirements = @('Administrator privileges, an available index in the active power plan and applicable hardware. Policy, power requests and platform capabilities affect the actual transition; a saved value alone proves no screen-off or suspend/resume.', 'Traditional sleep and Modern Standby interpret idle transitions differently. Battery presence, AC/DC conditions and effective GUI/managed behavior need target evidence. No reboot, immediate sleep or hibernation provisioning is performed.')
        OtherSupportedChoices = @('Native settings offer other durations. This ID currently exposes Never and the one legacy 30-minute preset; neither is a universal Windows default. Custom/extra durations remain implementation work.', 'No baseline/unset is declared. Saved restore preserves the exact captured index in the captured plan; it does not round to a named preset or restore a factory plan. The handler reactivates the same plan on apply and does not switch plans during restore.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-idle-timeout', 'https://support.microsoft.com/en-us/windows/experience/power-battery/power-settings-in-windows-11', 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/display--sleep--and-hibernate-idle-timers')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device active power plan: idle sleep timer, On battery (DC)'
        Behavior = 'Configuration'
        GuiPath = 'Settings > System > Power & battery (or Power) > Screen, sleep, & hibernate timeouts > On battery (DC) > Make my device sleep after; wording and availability vary by build/platform'
        GuiEffect = 'Never writes 0 seconds; FifteenMinutes writes 900 seconds (15 minutes) for On battery (DC). Never disables this idle-sleep timer, not manual/button/lid sleep or every other power transition. The other timer and power-source index remain independent.'
        Requirements = @('Administrator privileges, an available index in the active power plan and applicable hardware. Policy, power requests and platform capabilities affect the actual transition; a saved value alone proves no screen-off or suspend/resume.', 'Traditional sleep and Modern Standby interpret idle transitions differently. Battery presence, AC/DC conditions and effective GUI/managed behavior need target evidence. No reboot, immediate sleep or hibernation provisioning is performed.')
        OtherSupportedChoices = @('Native settings offer other durations. This ID currently exposes Never and the one legacy 15-minute preset; neither is a universal Windows default. Custom/extra durations remain implementation work.', 'No baseline/unset is declared. Saved restore preserves the exact captured index in the captured plan; it does not round to a named preset or restore a factory plan. The handler reactivates the same plan on apply and does not switch plans during restore.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-idle-timeout', 'https://support.microsoft.com/en-us/windows/experience/power-battery/power-settings-in-windows-11', 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/display--sleep--and-hibernate-idle-timers')
      }
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
      Name = 'Automatic recovery after boot-status failures'
      Kind = 'BootConfiguration'
      Category = 'Windows settings / Security'
      Description = 'Choose bootstatuspolicy for the current boot entry. IgnoreAllFailures ignores boot, shutdown and checkpoint failures and attempts normal startup; WindowsDefault removes the override. This does not disable Windows RE or factory reset. Exact saved BCD value/existence recovery is separate from reboot acceptance.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#boot-settings'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Current boot entry automatic recovery'
        Behavior = 'Configuration'
        GuiPath = 'No direct Settings control; BCD bootstatuspolicy'
        GuiEffect = 'IgnoreAllFailures ignores boot-status failures and attempts normal startup; WindowsDefault removes the override. Windows RE registration and manual recovery remain separate.'
        Requirements = @('Microsoft documents failed boot, shutdown and checkpoint handling. Boot effects need an isolated restart and independently verified recovery access.', 'Use an isolated disposable target with independent recovery media and encrypted-volume access. Do not automatically disable Secure Boot or BitLocker or trigger restart.')
        OtherSupportedChoices = @('Legacy DisableBootRecovery/EnableBootRecovery write IgnoreAllFailures/remove the element; these semantics match.', 'Saved-run restore recovers captured BCD value/existence; override removal does not prove the effective inherited policy.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#boot-settings')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Control Panel opening view'
        Behavior = 'Preference'
        GuiPath = 'Control Panel > View by'
        GuiEffect = 'SmallIcons, LargeIcons and Categories select one coordinated opening view; WindowsDefault removes both overrides, matching the legacy categories reverse'
        Requirements = @('Intended user with the Windows 11 Control Panel; this ID does not require administrator rights', 'The reference describes Control Panel, not the two registry preferences; current GUI and managed precedence need acceptance')
        OtherSupportedChoices = @('Explicit Categories differs from WindowsDefault; neither is saved-run restore', 'The current handler preserves both prior value types/absence and unrelated data; no shell refresh or restart is requested')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/shell/control-panel-applications')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: stored mouse acceleration preferences'
        Behavior = 'Preference'
        GuiPath = 'Settings > Bluetooth & devices > Mouse > Enhance pointer precision; related Mouse Properties > Pointer Options on applicable builds'
        GuiEffect = 'Enabled writes the legacy acceleration tuple 1/6/10; Disabled writes 0/0/0. WindowsDefault removes all three overrides. No session notification or UI refresh occurs; effective pointer behavior and GUI mapping need acceptance.'
        Requirements = @(
          'Windows 11 intended user; no administrator rights required. Pointer speed, vendor drivers and touchpad configuration are separate',
          'Microsoft documents the native control and acceleration API, not equivalence of these registry writes on every current build or device'
        )
        OtherSupportedChoices = @(
          'Baseline and unset remove the three overrides; they do not select a verified factory default. Literal and effective defaults are platform-defined',
          'Saved-run restore recovers each captured value, type and absence, including custom thresholds; selecting Enabled is not that recovery'
        )
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow', 'https://support.microsoft.com/en-us/windows/hardware/input-devices/change-mouse-settings')
      }
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
      Description = 'Represent the legacy UAC prompt pair as one choice. NoPrompt elevates administrators without consent; SecureConsent prompts for non-Windows binaries on the secure desktop. PromptOnSecureDesktop can also affect standard-user prompt placement; ConsentPromptBehaviorUser and EnableLUA are not changed. Partial failures retain both pre-change values. WindowsDefault removes both overrides; saved restore preserves their prior values/types and unrelated data. No elevated process, refresh or restart is initiated.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration'
      SettingPresentation = @{
        AppliesTo = 'Device: Administrator approval prompt and shared secure-desktop policy'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Security Policy > Local Policies > Security Options > User Account Control prompt behavior and secure desktop; related UAC slider'
        GuiEffect = 'NoPrompt writes ConsentPromptBehaviorAdmin=0 and PromptOnSecureDesktop=0; SecureConsent writes 5 and 1. The secure-desktop setting can affect standard-user prompts too, although the standard-user credential policy is not changed.'
        Requirements = @('Existing Windows 11 declaration only; no broader target support inferred from references. RIDE does not restart, upload samples or refresh the GUI.', 'Requires an administrator for policy writes; admin prompt behavior depends on Admin Approval Mode/EnableLUA and other UAC policies. NoPrompt allows administrative elevation without consent. No elevated process is provisioned by this setting.')
        OtherSupportedChoices = @('Legacy low/high selectors wrote these exact pairs. SecureConsent is the non-Windows-binary consent choice, not an always-notify maximum. WindowsDefault removes both overrides; exact restore retains each original value/type/absence.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy content-delivery permission'
        Behavior = 'Unverified'
        GuiPath = 'No verified one-to-one Windows Settings control'
        GuiEffect = 'Disabled writes ContentDeliveryAllowed=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled wrote 1, matching the explicit current state. This is not a master control for every Windows advertisement.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy OEM app-promotion preference'
        Behavior = 'Unverified'
        GuiPath = 'No verified one-to-one Windows Settings control'
        GuiEffect = 'Disabled writes OemPreInstalledAppsEnabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled wrote 1. Existing OEM applications are neither removed nor disabled.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy preinstalled-app promotion preference'
        Behavior = 'Unverified'
        GuiPath = 'No verified one-to-one Windows Settings control'
        GuiEffect = 'Disabled writes PreInstalledAppsEnabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled wrote 1. PreInstalledAppsEverEnabled bookkeeping is not owned; existing apps remain separate.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy silent suggested-app preference'
        Behavior = 'Unverified'
        GuiPath = 'No verified one-to-one Windows Settings control'
        GuiEffect = 'Disabled writes SilentInstalledAppsEnabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled wrote 1. This is not a general Store or Windows Update installation prohibition.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Unresolved content subscription channel 310093'
        Behavior = 'Unverified'
        GuiPath = 'No verified GUI control or feature label for channel 310093'
        GuiEffect = 'Disabled writes SubscribedContent-310093Enabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled removed this value. Use WindowsDefault for that reverse; explicit Enabled=1 differs.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Unresolved content subscription channel 314559'
        Behavior = 'Unverified'
        GuiPath = 'No verified GUI control or feature label for channel 314559'
        GuiEffect = 'Disabled writes SubscribedContent-314559Enabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled removed this value. Use WindowsDefault for that reverse; explicit Enabled=1 differs.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Unresolved content subscription channel 338387'
        Behavior = 'Unverified'
        GuiPath = 'No verified GUI control or feature label for channel 338387'
        GuiEffect = 'Disabled writes SubscribedContent-338387Enabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled removed this value. Use WindowsDefault for that reverse; explicit Enabled=1 differs.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Unresolved content subscription channel 338388'
        Behavior = 'Unverified'
        GuiPath = 'No verified GUI control or feature label for channel 338388'
        GuiEffect = 'Disabled writes SubscribedContent-338388Enabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled wrote 1, matching the explicit current state.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Unresolved content subscription channel 338389'
        Behavior = 'Unverified'
        GuiPath = 'No verified GUI control or feature label for channel 338389'
        GuiEffect = 'Disabled writes SubscribedContent-338389Enabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled wrote 1, matching the explicit current state.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Unresolved content subscription channel 338393'
        Behavior = 'Unverified'
        GuiPath = 'No verified GUI control or feature label for channel 338393'
        GuiEffect = 'Disabled writes SubscribedContent-338393Enabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled removed this value. Use WindowsDefault for that reverse; explicit Enabled=1 differs.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Unresolved content subscription channel 353694'
        Behavior = 'Unverified'
        GuiPath = 'No verified GUI control or feature label for channel 353694'
        GuiEffect = 'Disabled writes SubscribedContent-353694Enabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled wrote 1, matching the explicit current state.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Unresolved content subscription channel 353696'
        Behavior = 'Unverified'
        GuiPath = 'No verified GUI control or feature label for channel 353696'
        GuiEffect = 'Disabled writes SubscribedContent-353696Enabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled wrote 1, matching the explicit current state.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Unresolved content subscription channel 353698'
        Behavior = 'Unverified'
        GuiPath = 'No verified GUI control or feature label for channel 353698'
        GuiEffect = 'Disabled writes SubscribedContent-353698Enabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled removed this value. Use WindowsDefault for that reverse; explicit Enabled=1 differs.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy Settings suggestion preference'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Settings > Privacy & security > Recommendations & offers (General on older builds); mapping unverified'
        GuiEffect = 'Disabled writes SystemPaneSuggestionsEnabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled wrote 1. The current suggested-content option does not establish this legacy value as its complete control.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/privacy/privacy-settings-for-recommendations-offers-in-windows-11')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy finish-setting-up prompt preference'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Settings > System > Notifications > Additional settings; mapping unverified'
        GuiEffect = 'Disabled writes ScoobeSystemSettingEnabled=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enabled removed this value. WindowsDefault retains that reverse; explicit Enabled=1 differs.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/notifications-and-do-not-disturb-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy implicit typed-text learning preference'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Settings > Privacy & security > Inking & typing personalization; mapping unverified'
        GuiEffect = 'Restricted writes RestrictImplicitTextCollection=1; Allowed writes 0; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Restricted/Allowed wrote 1/0, matching the numeric pair. This does not enable Cortana or configure all diagnostic uploads.', 'Saved restore recovers registry type/value/absence, not learned words or training data that Windows may delete. Cortana app registration and speech services are separate.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/privacy/speech-voice-activation-inking-typing-and-privacy')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy implicit handwriting learning preference'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Settings > Privacy & security > Inking & typing personalization; mapping unverified'
        GuiEffect = 'Restricted writes RestrictImplicitInkCollection=1; Allowed writes 0; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Restricted/Allowed wrote 1/0, matching the numeric pair. This does not enable Cortana or configure all diagnostic uploads.', 'Saved restore recovers registry type/value/absence, not learned words or training data that Windows may delete. Cortana app registration and speech services are separate.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/privacy/speech-voice-activation-inking-typing-and-privacy')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy contact-name learning preference'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Settings > Privacy & security > Inking & typing personalization; exact contact-learning control unverified'
        GuiEffect = 'Disabled writes HarvestContacts=0; Enabled writes 1; WindowsDefault removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy EnableCortana removed HarvestContacts. WindowsDefault retains that reverse; Enabled=1 differs. This is not the app contacts-access permission.', 'Saved restore recovers registry type/value/absence, not learned words or training data that Windows may delete. Cortana app registration and speech services are separate.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/privacy/speech-voice-activation-inking-typing-and-privacy')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: NCSI active connectivity probing local configuration'
        Behavior = 'Configuration'
        GuiPath = 'No direct Settings switch; network-status display is an observed result'
        GuiEffect = 'Disabled writes EnableActiveProbing=0; Enabled writes 1. The separate NoActiveProbe policy can also restrict active tests; passive observation remains separate.'
        Requirements = @('Microsoft documents this registry switch and cautions that disabling probes can impair application connectivity decisions. A successful registry write proves neither network access nor the effective combined configuration.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('No matching EnableActiveProbing write was found in retained legacy/v2. Keep this separate from the legacy NoActiveProbe selector and its policy reverse; never count both as two completed legacy outcomes.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: MSRT offers through Windows Update'
        Behavior = 'Unverified'
        GuiPath = 'Related: Settings > Windows Update; no verified dedicated MSRT-offer toggle'
        GuiEffect = 'Disabled writes 1; Allowed writes 0. The current effect of this legacy registry preference is unverified. It does not disable Defender, run MSRT or remove installed tools. Baseline and unset remove the owned override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Administrator rights for the device write. RIDE does not refresh policy, restart, sign out, run updates or change services.', 'The Microsoft reference describes MSRT behavior but does not document DontOfferThroughWUAU. Current service/offer behavior requires evidence.')
        OtherSupportedChoices = @('Legacy EnableUpdateMSRT removed the value; WindowsDefault, not explicit Allowed, matches that reverse.', 'Keep update offering, installation, restart, sign-in and wake outcomes separate. A registry round trip establishes stored state only.')
        ReferenceUris = @('https://support.microsoft.com/en-us/servicing/os/windows/2021/01/remove-specific-prevalent-malware-with-windows-malicious-software-removal-tool-kb890830')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Driver-classified Windows quality updates'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage updates offered from Windows Update > Do not include drivers with Windows Updates'
        GuiEffect = 'Excluded writes 1; Included writes 0. This default concerns driver-classified update offers and does not block manual installation or independently controlled driver searches. Baseline and unset remove the owned override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Administrator rights for the device write. RIDE does not refresh policy, restart, sign out, run updates or change services.', 'Requires a supported policy edition: Windows 11 Pro, Enterprise, Education or IoT Enterprise. Existing update source and managed precedence still apply.')
        OtherSupportedChoices = @('Legacy DisableUpdateDriver also changed device metadata and DriverSearching/SearchOrderConfig. This ID owns only quality-update driver exclusion; its legacy reverse removes the value.', 'Keep update offering, installation, restart, sign-in and wake outcomes separate. A registry round trip establishes stored state only.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#excludewudriversinqualityupdate')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Applications associated with device metadata'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > System > Device Installation > Prevent automatic download of applications associated with device metadata'
        GuiEffect = 'Prevented writes 1. UserChoice writes 0 and delegates to Device Installation Settings; it does not force every metadata application to download. This is separate from driver packages. Baseline and unset remove the owned override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Administrator rights for the device write. RIDE does not refresh policy, restart, sign out, run updates or change services.', 'Requires Windows 11 Pro, Enterprise, Education or IoT Enterprise. The device policy can override the local Device Installation Settings choice; current GUI and consumer behavior need acceptance.')
        OtherSupportedChoices = @('The legacy driver bundle wrote this value to 1 and removed it on reverse. Its separate driver-search and quality-update controls are not implicitly applied.', 'Keep update offering, installation, restart, sign-in and wake outcomes separate. A registry round trip establishes stored state only.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceinstallation#preventdevicemetadatafromnetwork')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Automatic Updates download-mode policy element'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage end user experience > Configure Automatic Updates'
        GuiEffect = 'NotifyDownload writes AUOptions=2; AutoDownload writes 3. This ID does not set the accompanying NoAutoUpdate element or trigger an update scan, download or installation. Baseline and unset remove the owned override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Administrator rights for the device write. RIDE does not refresh policy, restart, sign out, run updates or change services.', 'AUOptions is one element of a larger policy. NoAutoUpdate, managed sources and current update policies can affect the result; configured bytes do not prove effective download/restart behavior.')
        OtherSupportedChoices = @('Legacy EnableUpdateAutoDownload removed AUOptions, rather than writing 3. WindowsDefault matches that reverse. Scheduled-install values and server-only alternatives are not added by this review.', 'Keep update offering, installation, restart, sign-in and wake outcomes separate. A registry round trip establishes stored state only.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Automatic sign-in and locking of the last interactive user after restart'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > System > Logon > Sign-in and lock last interactive user automatically after a restart'
        GuiEffect = 'Disabled writes 1; Enabled writes 0. This permits or denies the sign-in-and-lock feature; it neither initiates a restart/sign-in nor unlocks the user session. Baseline and unset remove the owned override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Administrator rights for the device write. RIDE does not refresh policy, restart, sign out, run updates or change services.', 'Requires Windows 11 Pro, Enterprise, Education or IoT Enterprise. Device join state, prior sign-out and the separate ARSO mode/BitLocker conditions affect execution. No change to protectors or ARSO mode is made.')
        OtherSupportedChoices = @('Legacy EnableAutoRestartSignOn removed the override. WindowsDefault matches that reverse; explicit Enabled writes 0. Automatic restart scheduling remains separate.', 'Keep update offering, installation, restart, sign-in and wake outcomes separate. A registry round trip establishes stored state only.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#allowautomaticrestartsignon')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Lock-screen display'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > Control Panel > Personalization > Do not display the lock screen'
        GuiEffect = 'Disabled writes NoLockScreen=1; Enabled writes 0. This affects the lock-screen display, not authentication or the ability to lock a session.'
        Requirements = @('Microsoft documents the mapping and its interaction with the Ctrl+Alt+Delete requirement. Edition, managed-policy and actual sign-in behavior require acceptance.', 'Retain current target declarations. No sign-out, lock, restart, shutdown or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Enable removed NoLockScreen. WindowsDefault preserves that reverse; explicit Enabled=0 differs. The RS1 scheduled-task workaround remains omitted.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from Baseline and override removal.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_nolockscreen')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Detailed startup, shutdown, logon and logoff messages'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > System > Display highly detailed status messages'
        GuiEffect = 'Enabled writes VerboseStatus=1; Disabled writes 0. WindowsDefault removes the policy value.'
        Requirements = @('Microsoft documents the mapping; the remove-status-messages policy can suppress the result. No startup, shutdown, sign-in or sign-out is triggered.', 'Retain current target declarations. No sign-out, lock, restart, shutdown or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy client Enable wrote 1 and Disable removed; Server Enable removed and Disable wrote 0. Current Windows 11 explicit Disabled differs from legacy client reverse; WindowsDefault matches removal. No Server target is added.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from Baseline and override removal.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-logon#verbosestatus')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Mapped drive links between linked UAC logon sessions'
        Behavior = 'Configuration'
        GuiPath = 'No dedicated Settings control; verify in the intended normal and elevated sessions'
        GuiEffect = 'Enabled writes EnableLinkedConnections=1; Disabled writes 0. It does not create a drive mapping, grant share permissions or link unrelated credentials.'
        Requirements = @('Microsoft documents the value and a restart. Prompt-for-credentials elevation can create another session outside the linked pair. No restart or credential use is performed.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy Disable removed the value; WindowsDefault matches removal. Explicit Disabled=0 differs. Recovery restores the value, not the remote session, credential or mapped-drive contents.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current user: Attachment Manager source-zone preservation'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'User Configuration > Administrative Templates > Windows Components > Attachment Manager > Do not preserve zone information in file attachments'
        GuiEffect = 'Discard writes SaveZoneInformation=1; Preserve writes 2. This controls future attachment zone metadata on supported file systems, not every downloader.'
        Requirements = @('Microsoft documents the policy mapping and security effect. Discard can weaken later origin-based security checks; existing zone metadata and SmartScreen remain untouched.', 'Retain current target declarations. No sign-out, lock, restart, shutdown or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy DisableDownloadBlocking wrote 1; Enable removed the value. WindowsDefault matches removal; Preserve=2 is explicit.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from Baseline and override removal.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-attachmentmanager#donotpreservezoneinformation')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Recycle Bin system icon on the desktop'
        Behavior = 'Preference'
        GuiPath = 'Settings > Personalization > Themes > Desktop icon settings'
        GuiEffect = 'Shown writes 0 and Hidden writes 1 for this one system icon. The separate all-desktop-icons preference can suppress its display. No shortcut or content is deleted.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents the desktop option, not the NewStartPanel GUID mapping. Current-build icon rendering and managed precedence need acceptance.')
        OtherSupportedChoices = @('Legacy Shown removed the override; WindowsDefault matches that reverse, whereas Shown writes 0. The legacy ClassicStartMenu companion remains excluded from the Windows 11 model.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: This PC system icon on the desktop'
        Behavior = 'Preference'
        GuiPath = 'Settings > Personalization > Themes > Desktop icon settings'
        GuiEffect = 'Shown writes 0 and Hidden writes 1 for this one system icon. The separate all-desktop-icons preference can suppress its display. No shortcut or content is deleted.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents the desktop option, not the NewStartPanel GUID mapping. Current-build icon rendering and managed precedence need acceptance.')
        OtherSupportedChoices = @('Legacy Hidden removed the override; WindowsDefault matches that reverse, whereas Hidden writes 1. The legacy ClassicStartMenu companion remains excluded from the Windows 11 model.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: user files system icon on the desktop'
        Behavior = 'Preference'
        GuiPath = 'Settings > Personalization > Themes > Desktop icon settings'
        GuiEffect = 'Shown writes 0 and Hidden writes 1 for this one system icon. The separate all-desktop-icons preference can suppress its display. No shortcut or content is deleted.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents the desktop option, not the NewStartPanel GUID mapping. Current-build icon rendering and managed precedence need acceptance.')
        OtherSupportedChoices = @('Legacy Hidden removed the override; WindowsDefault matches that reverse, whereas Hidden writes 1. The legacy ClassicStartMenu companion remains excluded from the Windows 11 model.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Control Panel system icon on the desktop'
        Behavior = 'Preference'
        GuiPath = 'Settings > Personalization > Themes > Desktop icon settings'
        GuiEffect = 'Shown writes 0 and Hidden writes 1 for this one system icon. The separate all-desktop-icons preference can suppress its display. No shortcut or content is deleted.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents the desktop option, not the NewStartPanel GUID mapping. Current-build icon rendering and managed precedence need acceptance.')
        OtherSupportedChoices = @('Legacy Hidden removed the override; WindowsDefault matches that reverse, whereas Hidden writes 1. The legacy ClassicStartMenu companion remains excluded from the Windows 11 model.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Network system icon on the desktop'
        Behavior = 'Preference'
        GuiPath = 'Settings > Personalization > Themes > Desktop icon settings'
        GuiEffect = 'Shown writes 0 and Hidden writes 1 for this one system icon. The separate all-desktop-icons preference can suppress its display. No shortcut or content is deleted.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents the desktop option, not the NewStartPanel GUID mapping. Current-build icon rendering and managed precedence need acceptance.')
        OtherSupportedChoices = @('Legacy Hidden removed the override; WindowsDefault matches that reverse, whereas Hidden writes 1. The legacy ClassicStartMenu companion remains excluded from the Windows 11 model.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows')
      }
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
      Name = 'Desktop version-label request (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Control the legacy desktop version-label preference. Microsoft documents system version discovery, not this registry mapping; desktop rendering requires target review and may need a new sign-in. No reboot or shell restart.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#system---about'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy desktop version-label request'
        Behavior = 'Unverified'
        GuiPath = 'No verified current GUI equivalent; Settings > System > About is the related version-information surface'
        GuiEffect = 'Shown writes PaintDesktopVersion=1; Hidden writes 0. Whether the desktop renders a label on this Windows build remains unverified.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents version discovery rather than this registry value. A new sign-in may be needed; RIDE does not sign out or restart Explorer.')
        OtherSupportedChoices = @('The legacy pair also wrote 1/0. WindowsDefault removes the override; saved restore preserves its exact prior value/type/absence.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#system---about')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Network selection before sign-in'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > System > Logon > Do not display network selection UI'
        GuiEffect = 'Hidden writes DontDisplayNetworkSelectionUI=1; Shown writes 0. It does not disable adapters or established network connections.'
        Requirements = @('Microsoft documents this policy. Verify applicable edition, managed precedence and sign-in access with an independent management/recovery path.', 'Retain current target declarations. No sign-out, lock, restart, shutdown or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Show removed the override. WindowsDefault preserves removal; Shown=0 is explicit.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from Baseline and override removal.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#dontdisplaynetworkselectionui')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Shutdown availability before sign-in'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Security Policy > Local Policies > Security Options > Shutdown: Allow system to be shut down without having to log on'
        GuiEffect = 'Enabled writes ShutdownWithoutLogon=1; Disabled writes 0. No shutdown is initiated and signed-in user rights remain separate.'
        Requirements = @('The Microsoft security policy describes sign-in behavior. Effective managed policy and actual sign-in screen behavior need isolated acceptance.', 'Retain current target declarations. No sign-out, lock, restart, shutdown or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy enabled/disabled values match 1/0. WindowsDefault removes the override; it is not a command to shut down.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from Baseline and override removal.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#shutdown_allowsystemtobeshutdownwithouthavingtologon')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Recently added applications in Start'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Settings > Personalization > Start; related Remove Recently added list policy'
        GuiEffect = 'Hidden writes HideRecentlyAddedApps=1; UserChoice writes 0; WindowsDefault removes the override.'
        Requirements = @('Microsoft documents this exact policy, supported editions and shell/restart requirements. No restart or shell termination is performed.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy ShowRecentlyAddedApps removed the override. WindowsDefault matches; UserChoice=0 is explicit.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start#hiderecentlyaddedapps')
      }
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
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Windows 11 taskbar alignment'
        Behavior = 'Unverified'
        GuiPath = 'Settings > Personalization > Taskbar > Taskbar behaviors'
        GuiEffect = 'Left writes TaskbarAl=0; Centered writes 1; WindowsDefault removes the preference.'
        Requirements = @('The reference documents the visible option, not the value mapping. Verify current build and shell behavior.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy center selector removed TaskbarAl; current Centered=1 differs, WindowsDefault matches removal.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: camera access'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access the camera'
        GuiEffect = 'ForceDeny writes 2; ForceAllow writes 1; UserControl writes 0; WindowsDefault, Baseline and unset remove the value. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'Camera hardware availability and desktop-program access remain separate.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The explicit 0/1/2 states are distinct from an absent policy; none establishes a global hardware switch.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesscamera')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: microphone access'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access the microphone'
        GuiEffect = 'ForceDeny writes 2; ForceAllow writes 1; UserControl writes 0; WindowsDefault, Baseline and unset remove the value. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'Microphone hardware availability, mute and desktop-program access remain separate.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The explicit 0/1/2 states are distinct from an absent policy; none establishes a global hardware switch.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessmicrophone')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Local Fast startup preference'
        Behavior = 'Configuration'
        GuiPath = 'Control Panel > Power Options > Choose what the power buttons do > Turn on fast startup'
        GuiEffect = 'Enabled writes HiberbootEnabled=1; Disabled writes 0. WindowsDefault removes the local preference.'
        Requirements = @('Microsoft documents this exact value. Hibernation, hardware and the Require use of fast startup policy affect the result. No hibernation file, shutdown or restart is created or triggered.', 'Retain current target declarations. No sign-out, lock, restart, shutdown or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy 1/0 values match. Removing the preference is separate from setting Disabled; actual shutdown/startup behavior remains acceptance work.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from Baseline and override removal.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/unified-write-filter/hibernate-once-resume-many-horm#how-to-disable-fast-startup')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Automatic restart after system failure'
        Behavior = 'Configuration'
        GuiPath = 'System Properties > Advanced > Startup and Recovery > Automatically restart'
        GuiEffect = 'Enabled writes CrashControl/AutoReboot=1; Disabled writes 0. It changes neither crash-dump configuration nor ordinary update restart behavior.'
        Requirements = @('The Microsoft Win32_OSRecoveryConfiguration AutoReboot property documents the registry mapping. A deliberate crash is not part of discovery or this operation.', 'Retain current target declarations. No sign-out, lock, restart, shutdown or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy 1/0 values match. WindowsDefault removes the override; saved restore recovers the original value without inducing a crash.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from Baseline and override removal.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-osrecoveryconfiguration')
      }
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
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/apps/using-the-clipboard'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: local clipboard history'
        Behavior = 'Preference'
        GuiPath = 'Settings > System > Clipboard > Clipboard history; Windows key + V'
        GuiEffect = 'Enabled writes 1 and Disabled writes 0 to the history preference; WindowsDefault, Baseline and unset remove it. Machine AllowClipboardHistory policy may gray the native control and prevent history. This preference neither clears saved content nor enables cross-device synchronization.'
        Requirements = @('Windows 11 clipboard-history feature and the intended user context. Microsoft documents UI behavior, not the legacy EnableClipboardHistory registry mapping; current preference/GUI parity remains unverified.', 'History may contain sensitive copied data. Saved restore recovers only the preference; it cannot reconstruct lost clipboard entries or pin state. Sync account requirements apply separately to cross-device sync.')
        OtherSupportedChoices = @('Native clipboard clear/delete/pin and cross-device synchronization remain separate choices; no content or account action is performed.', 'Legacy DisableClipboardHistory removed the override, corresponding to WindowsDefault here. The published Disabled=0 state is an explicit preference and remains distinct.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/apps/using-the-clipboard', 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience#allowclipboardhistory')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/properties/props-system-ispinnedtonamespacetree'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Libraries namespace pin in the navigation pane'
        Behavior = 'Preference'
        GuiPath = 'File Explorer Options > View > Navigation pane > Show libraries'
        GuiEffect = 'Shown writes System.IsPinnedToNameSpaceTree=1; Hidden writes 0 at the Libraries CLSID. Library definitions, member folders and their contents are retained.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents the Boolean namespace-pin property, not this exact CLSID registry registration. Current Explorer rendering and policy interaction remain acceptance work.')
        OtherSupportedChoices = @('Legacy Hide removed the value; WindowsDefault matches removal. Explicit Hidden=0 is a separate current choice; exact restore preserves prior type/value/absence.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/properties/props-system-ispinnedtonamespacetree')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Empty removable-drive entries in File Explorer'
        Behavior = 'Preference'
        GuiPath = 'File Explorer Options > View > Hide empty drives'
        GuiEffect = 'Visible writes HideDrivesWithNoMedia=0; Hidden writes 1. This is a view preference, not a storage-access rule or a command to remove drives.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'The Microsoft settings schema documents HideDrivesWithNoMedia behavior, not this registry mapping. Test with suitable removable media/hardware and relevant Explorer views.')
        OtherSupportedChoices = @('Legacy Hide removed the override; WindowsDefault matches that reverse, while Hidden writes 1. Saved restore preserves the captured value/type/absence.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: folder merge prompts'
        Behavior = 'Preference'
        GuiPath = 'File Explorer > More (...) > Options > View > Hide folder merge conflicts'
        GuiEffect = 'Shown writes 0; Hidden writes 1. Duplicate-file replacement prompts are separate; this preference does not authorize a copy or resolve collisions. WindowsDefault, Baseline and unset remove the override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 File Explorer in the intended execution account; no administrator privilege is required. RIDE does not restart Explorer, sign out or force a refresh. Reopen windows manually as needed during acceptance.', 'Microsoft documents the folder option in backup data, not the HideMergeConflicts registry mapping. Managed precedence, current GUI state and editability remain unverified.')
        OtherSupportedChoices = @('Legacy HideFolderMergeConflicts removed the value. Its matching reverse is WindowsDefault, not the explicit Hidden state.', 'This control is independently selectable. It does not apply an Explorer preset or change adjacent preferences.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: navigation pane contents'
        Behavior = 'Preference'
        GuiPath = 'File Explorer > More (...) > Options > View > Navigation pane > Show all folders'
        GuiEffect = 'Enabled writes 1; Disabled writes 0 for showing the broader folder tree. Automatic expansion and individual namespace icons remain independent. WindowsDefault, Baseline and unset remove the override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 File Explorer in the intended execution account; no administrator privilege is required. RIDE does not restart Explorer, sign out or force a refresh. Reopen windows manually as needed during acceptance.', 'Microsoft documents the navigation option in backup data, not the NavPaneShowAllFolders registry mapping. Managed precedence, current GUI state and editability remain unverified.')
        OtherSupportedChoices = @('Legacy HideNavPaneAllFolders removed the value; WindowsDefault preserves that distinction from explicit Disabled.', 'This control is independently selectable. It does not apply an Explorer preset or change adjacent preferences.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: folder window title'
        Behavior = 'Preference'
        GuiPath = 'File Explorer > More (...) > Options > View > Display the full path in the title bar'
        GuiEffect = 'Shown writes 1; Hidden writes 0. This concerns the window title, not address-bar formatting or a guarantee about each tab caption. WindowsDefault, Baseline and unset remove the override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 File Explorer in the intended execution account; no administrator privilege is required. RIDE does not restart Explorer, sign out or force a refresh. Reopen windows manually as needed during acceptance.', 'Microsoft maps the preference attribute to CabinetState/FullPath; current Windows 11 title/tab rendering still needs GUI evidence. Managed precedence, current GUI state and editability remain unverified.')
        OtherSupportedChoices = @('Legacy HideExplorerTitleFullPath removed the value; its reverse corresponds to WindowsDefault rather than explicit Hidden.', 'This control is independently selectable. It does not apply an Explorer preset or change adjacent preferences.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: protected operating system file visibility in File Explorer'
        Behavior = 'Preference'
        GuiPath = 'File Explorer Options > View > Hide protected operating system files'
        GuiEffect = 'Visible requests showing protected files; Hidden requests hiding them; WindowsDefault removes only this override. The separate hidden-files choice can still limit visibility'
        Requirements = @('Intended user with Windows 11 File Explorer; this ID does not require administrator rights', 'The reference describes folder visibility preferences; current GUI, interaction with hidden files and managed precedence need acceptance')
        OtherSupportedChoices = @('Hidden files remain a separate setting; no automatic combined rewrite', 'File attributes, permissions and contents are unchanged; saved-run restore preserves the prior value type/data/absence')
        ReferenceUris = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: folder process preference'
        Behavior = 'Preference'
        GuiPath = 'File Explorer > More (...) > Options > View > Launch folder windows in a separate process'
        GuiEffect = 'Enabled writes 1; Disabled writes 0. RIDE requests the folder option; it does not create a process or guarantee one process per window/tab or a security boundary. WindowsDefault, Baseline and unset remove the override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 File Explorer in the intended execution account; no administrator privilege is required. RIDE does not restart Explorer, sign out or force a refresh. Reopen windows manually as needed during acceptance.', 'Microsoft maps SeparateProcess. Current process topology, crash isolation and memory effects are not established by a registry round trip. Managed precedence, current GUI state and editability remain unverified.')
        OtherSupportedChoices = @('The legacy pair wrote 1/0 explicitly. WindowsDefault additionally removes the override; actual process grouping requires native observation.', 'This control is independently selectable. It does not apply an Explorer preset or change adjacent preferences.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: folder windows at next logon'
        Behavior = 'Preference'
        GuiPath = 'File Explorer > More (...) > Options > View > Restore previous folder windows at logon'
        GuiEffect = 'Enabled writes 1; Disabled writes 0. This requests restoration of prior folder windows at a later sign-in; it does not reopen them now or restore every application session. WindowsDefault, Baseline and unset remove the override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 File Explorer in the intended execution account; no administrator privilege is required. RIDE does not restart Explorer, sign out or force a refresh. Reopen windows manually as needed during acceptance.', 'Microsoft maps PersistBrowsers but its protocol description alone does not establish current logon behavior. Sign-in settings and build behavior need acceptance. Managed precedence, current GUI state and editability remain unverified.')
        OtherSupportedChoices = @('Legacy DisableRestoreFldrWindows removed PersistBrowsers. WindowsDefault retains that reverse; explicit Disabled differs.', 'This control is independently selectable. It does not apply an Explorer preset or change adjacent preferences.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Explorer sharing interface'
        Behavior = 'Preference'
        GuiPath = 'File Explorer > More (...) > Options > View > Use Sharing Wizard (Recommended)'
        GuiEffect = 'Enabled writes 1; Disabled writes 0. This changes the requested interface, leaving existing shares, NTFS/share permissions and discovery/firewall settings untouched. WindowsDefault, Baseline and unset remove the override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 File Explorer in the intended execution account; no administrator privilege is required. RIDE does not restart Explorer, sign out or force a refresh. Reopen windows manually as needed during acceptance.', 'Microsoft maps SharingWizardOn. Domain/edition and policy can affect the available sharing interface; a checked option is not proof of network access. Managed precedence, current GUI state and editability remain unverified.')
        OtherSupportedChoices = @('Legacy EnableSharingWizard removed SharingWizardOn. WindowsDefault matches that reverse; explicit Enabled writes 1. Advanced sharing and peer access require separate review.', 'This control is independently selectable. It does not apply an Explorer preset or change adjacent preferences.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/a6ca3a17-1971-4b22-bf3b-e1a5d5c50fca')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: item selection'
        Behavior = 'Preference'
        GuiPath = 'File Explorer > More (...) > Options > View > Use check boxes to select items; also View > Show > Item check boxes where available'
        GuiEffect = 'Shown writes 1; Hidden writes 0. Selection boxes assist choosing items; touch-oriented behavior can still show them despite the stored preference. WindowsDefault, Baseline and unset remove the override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 File Explorer in the intended execution account; no administrator privilege is required. RIDE does not restart Explorer, sign out or force a refresh. Reopen windows manually as needed during acceptance.', 'Microsoft documents the option in backup data, not AutoCheckSelect. The older protocol uses UseCheckBoxes instead; do not substitute that mapping or infer current touch behavior. Managed precedence, current GUI state and editability remain unverified.')
        OtherSupportedChoices = @('The legacy pair wrote 1/0 explicitly. Keyboard/mouse selection remains available; WindowsDefault removes only this override.', 'This control is independently selectable. It does not apply an Explorer preset or change adjacent preferences.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: thumbnail rendering'
        Behavior = 'Preference'
        GuiPath = 'File Explorer > More (...) > Options > View > Always show icons, never thumbnails'
        GuiEffect = 'Enabled writes IconsOnly=0 to permit thumbnails; Disabled writes 1 for icons only. View size, content providers and policy still affect what is rendered. WindowsDefault, Baseline and unset remove the override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 File Explorer in the intended execution account; no administrator privilege is required. RIDE does not restart Explorer, sign out or force a refresh. Reopen windows manually as needed during acceptance.', 'Microsoft maps IconsOnly. Actual rendering requires representative content/providers and a thumbnail-capable view; file lifecycle tests do not prove display behavior. Managed precedence, current GUI state and editability remain unverified.')
        OtherSupportedChoices = @('Legacy EnableThumbnails/DisableThumbnails wrote 0/1. Thumbnail caching, network thumbnail databases and preview-pane handlers remain independent; no cache cleanup is performed.', 'This control is independently selectable. It does not apply an Explorer preset or change adjacent preferences.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/a6ca3a17-1971-4b22-bf3b-e1a5d5c50fca')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Run as different user in Start'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'User Configuration > Administrative Templates > Start Menu and Taskbar > Show Run as different user command on Start'
        GuiEffect = 'Enabled writes ShowRunAsDifferentUserInStart=1; Disabled writes 0; WindowsDefault removes it.'
        Requirements = @('Microsoft documents user scope and supporting applications. This does not store credentials or launch another identity.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy wrote/removed the same value in HKLM; the maintained operation intentionally uses documented HKCU. Existing legacy HKLM overrides are not owned or removed.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-startmenu#showrunasdifferentuserinstart')
      }
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
      Description = 'Set the device App Privacy default for background execution to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This does not stop desktop services or startup programs. Legacy EnableUWPBackgroundApps also cleared user per-app Disabled/DisabledByUser values; this operation owns only the device policy and leaves those values intact.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsruninbackground'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: background execution'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps run in the background'
        GuiEffect = 'Disabled writes 2 to deny background execution; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This does not stop desktop services or startup programs. Legacy EnableUWPBackgroundApps also cleared user per-app Disabled/DisabledByUser values; this operation owns only the device policy and leaves those values intact.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsruninbackground')
      }
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
      Description = 'Set the device App Privacy default for activation by voice to deny, or remove this policy override. The general and locked-session voice policies must be evaluated together. Voice activation needs a compatible installed app and microphone. This does not install or restore a retired assistant. The locked-session policy is an additional independent restriction.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsactivatewithvoice'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: activation by voice'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps activate with voice'
        GuiEffect = 'Disabled writes 2 to deny activation by voice; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. The general and locked-session voice policies must be evaluated together. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'Voice activation needs a compatible installed app and microphone. This does not install or restore a retired assistant. The locked-session policy is an additional independent restriction.', 'Current app availability, locked-session behavior and effective policy require disposable-target acceptance.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy DisableUWPVoiceActivation wrote both voice policies to 2; EnableUWPVoiceActivation removed both. These IDs expose general activation and the additional locked-session restriction separately.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsactivatewithvoice')
      }
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
      Description = 'Set the device App Privacy default for activation by voice while locked to deny, or remove this policy override. The general and locked-session voice policies must be evaluated together. General voice activation must also permit the feature. This does not unlock Windows, enable the microphone or change general voice activation.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsactivatewithvoiceabovelock'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: activation by voice while locked'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps activate with voice while the system is locked'
        GuiEffect = 'Disabled writes 2 to deny activation by voice while locked; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. The general and locked-session voice policies must be evaluated together. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'General voice activation must also permit the feature. This does not unlock Windows, enable the microphone or change general voice activation.', 'Current app availability, locked-session behavior and effective policy require disposable-target acceptance.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy DisableUWPVoiceActivation wrote both voice policies to 2; EnableUWPVoiceActivation removed both. These IDs expose general activation and the additional locked-session restriction separately.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsactivatewithvoiceabovelock')
      }
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
      Description = 'Set the device App Privacy default for reading notifications to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This controls app access to notifications, not the delivery or display of all notification banners.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessnotifications'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: reading notifications'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access notifications'
        GuiEffect = 'Disabled writes 2 to deny reading notifications; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This controls app access to notifications, not the delivery or display of all notification banners.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessnotifications')
      }
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
      Description = 'Set the device App Privacy default for account information access to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This concerns app access to account information, not creating accounts, sign-in or changing credentials.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessaccountinfo'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: account information access'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access account information'
        GuiEffect = 'Disabled writes 2 to deny account information access; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This concerns app access to account information, not creating accounts, sign-in or changing credentials.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessaccountinfo')
      }
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
      Description = 'Set the device App Privacy default for contacts access to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Existing contacts and their synchronization are not removed or configured.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesscontacts'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: contacts access'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access contacts'
        GuiEffect = 'Disabled writes 2 to deny contacts access; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'Existing contacts and their synchronization are not removed or configured.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesscontacts')
      }
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
      Description = 'Set the device App Privacy default for calendar access to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Existing calendar data, accounts and synchronization are not removed or configured.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesscalendar'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: calendar access'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access the calendar'
        GuiEffect = 'Disabled writes 2 to deny calendar access; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'Existing calendar data, accounts and synchronization are not removed or configured.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesscalendar')
      }
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
      Name = 'Phone call permission for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the device App Privacy default for making phone calls to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This does not configure phone hardware, subscriptions or all Phone Link functions.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessphone'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: making phone calls'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps make phone calls'
        GuiEffect = 'Disabled writes 2 to deny making phone calls; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This does not configure phone hardware, subscriptions or all Phone Link functions.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessphone')
      }
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
      Description = 'Set the device App Privacy default for call history access to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This controls access, not deletion of call records.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesscallhistory'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: call history access'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access call history'
        GuiEffect = 'Disabled writes 2 to deny call history access; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This controls access, not deletion of call records.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesscallhistory')
      }
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
      Description = 'Set the device App Privacy default for email access to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This does not remove accounts/messages or configure a mail client.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessemail'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: email access'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access email'
        GuiEffect = 'Disabled writes 2 to deny email access; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This does not remove accounts/messages or configure a mail client.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessemail')
      }
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
      Description = 'Set the device App Privacy default for task data access to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This concerns app task data, not Task Scheduler tasks or running processes.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesstasks'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: task data access'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access Tasks'
        GuiEffect = 'Disabled writes 2 to deny task data access; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This concerns app task data, not Task Scheduler tasks or running processes.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccesstasks')
      }
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
      Description = 'Set the device App Privacy default for messaging access to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This does not remove existing messages or configure communications accounts.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessmessaging'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: messaging access'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access messaging'
        GuiEffect = 'Disabled writes 2 to deny messaging access; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This does not remove existing messages or configure communications accounts.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessmessaging')
      }
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
      Name = 'Radio control permission for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the device App Privacy default for control of radios to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This controls app permission to control radios; it does not directly switch Wi-Fi or Bluetooth on or off.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessradios'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: control of radios'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps control radios'
        GuiEffect = 'Disabled writes 2 to deny control of radios; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This controls app permission to control radios; it does not directly switch Wi-Fi or Bluetooth on or off.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsaccessradios')
      }
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
      Name = 'Unpaired-device communication for apps'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the device App Privacy default for communication with unpaired devices to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This concerns unpaired-device communication, not general cloud synchronization or the radio power state.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappssyncwithdevices'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: communication with unpaired devices'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps communicate with unpaired devices'
        GuiEffect = 'Disabled writes 2 to deny communication with unpaired devices; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This concerns unpaired-device communication, not general cloud synchronization or the radio power state.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappssyncwithdevices')
      }
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
      Name = 'Other-app diagnostic information access'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Set the device App Privacy default for diagnostic information about other apps to deny, or remove this policy override. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. This concerns information about other Windows apps, not the device diagnostic-data upload level.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsgetdiagnosticinfo'
      SettingPresentation = @{
        AppliesTo = 'Device policy for Windows apps: diagnostic information about other apps'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access diagnostic information about other apps'
        GuiEffect = 'Disabled writes 2 to deny diagnostic information about other apps; Enabled, Baseline and unset remove the policy override, without writing ForceAllow. Enforced choices restrict user changes for covered apps; removal returns control subject to other policy. Per-app policy lists take precedence over this default; this ID neither reads nor edits those lists. Saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Windows 11 Pro, Enterprise, Education or IoT Enterprise; administrator rights for the device write. Edition support is a policy prerequisite, not new target acceptance.', 'This concerns information about other Windows apps, not the device diagnostic-data upload level.', 'An already-open app may need to be reopened or the device restarted to consume policy changes. RIDE does neither automatically. Actual app coverage and effective managed policy remain unverified.')
        OtherSupportedChoices = @('The platform also defines UserControl=0 and ForceAllow=1; this stable two-state ID does not expose those additional choices.', 'Legacy disable wrote 2 and enable removed this default value. Existing per-app exceptions remain separately owned.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsgetdiagnosticinfo')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-settings#devices'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: AutoPlay media/device preference'
        Behavior = 'Preference'
        GuiPath = 'Settings > Bluetooth & devices > AutoPlay on Windows 11; ms-settings:autoplay; Server UI availability requires separate acceptance'
        GuiEffect = 'Disabled writes DisableAutoplay=1; Enabled and Baseline write 0. This preference does not enforce a machine policy or bypass drive-type restrictions. The related toggle remains subject to management; immediate GUI refresh is unverified.'
        Requirements = @('Windows shell AutoPlay support and the intended user context; media handlers and device type affect behavior. No account subscription is required by this preference.', 'Microsoft documents the Settings page and AutoPlay choices, not this DisableAutoplay registry mapping. Mapping and current GUI/media behavior remain acceptance items.')
        OtherSupportedChoices = @('Per-media default actions are separate native choices and remain unchanged. Machine/user AutoPlay drive policies are different controls.', 'No override-removal state is declared for this ID; Baseline is explicit Enabled. Saved restore recovers the captured value/type/absence.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-settings#devices', 'https://support.microsoft.com/en-us/windows/experience/backup-recovery/windows-backup-settings-catalog', 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-autoplay#turnoffautoplay')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-autoplay#turnoffautoplay'
      SettingPresentation = @{
        AppliesTo = 'All users on this device: AutoPlay/AutoRun drive-type restriction'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Group Policy > Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off AutoPlay'
        GuiEffect = 'Disabled writes the all-drive-types mask 255. Enabled, Baseline and unset remove this machine override; they do not enable every drive or autorun command. User preferences and other restrictions may still prevent actions. Current Settings toggle editability remains unverified.'
        Requirements = @('Administrator privileges for the fixed machine scope. Microsoft lists the policy on Pro, Enterprise, Education and IoT Enterprise; Home policy consumption and Server shell/media behavior need separate evidence.', 'Policy changes require shell/session refresh according to the AutoRun reference; RIDE does not restart Explorer. This controls drive-type handling, not execution prevention for manually opened files.')
        OtherSupportedChoices = @('Microsoft exposes a narrower CD/removable-media restriction and user policy; this ID retains only all-drive Disabled and machine override removal.', 'Set the default behavior for AutoRun uses a different policy. The AutoPlay user preference and device/media handlers remain separate. Saved restore recovers the original mask/type/absence.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-autoplay#turnoffautoplay', 'https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg')
      }
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
      Name = 'Input diagnostics: inking and typing sample preference (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Privacy'
      Description = 'Write HKCU Input/TIPC Enabled=0, the legacy preference intended to suppress inking and typing diagnostic samples. Published Enabled removes the override rather than writing 1. Microsoft documents Improve inking and typing, not this registry mapping. Current Windows 11 effect remains unverified; this is separate from personal dictionaries and does not disable all diagnostics.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/privacy/diagnostics-feedback-and-privacy-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy inking and typing diagnostic-sample preference'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Settings > Privacy & security > Diagnostics & feedback > Improve inking and typing; mapping unverified'
        GuiEffect = 'Disabled writes Input/TIPC Enabled=0; published Enabled removes the value. Exact current GUI effect and editability remain unverified.'
        Requirements = @('The Microsoft reference describes the related feature area, not this individual registry mapping. Keep experimental controls out of recommended profiles until current-build evidence establishes the effect.', 'Retain existing target declarations; account, edition, build and managed policy may change effective behavior. No process restart, sign-out, app installation or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy DisableInkingAndTypingData wrote 0 and supplied no paired reverse. Published Enabled and baseline remove the override; removal does not prove that diagnostic sampling is enabled.', 'Saved restore recovers registry type/value/absence. Baseline or override removal does not reproduce every legacy bundle action.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/privacy/diagnostics-feedback-and-privacy-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Resolved tools-directory Defender Antivirus scan exclusion'
        Behavior = 'Configuration'
        GuiPath = 'Windows Security > Virus & threat protection > Manage settings > Exclusions'
        GuiEffect = 'Present adds the selected path to scan exclusions and may create its directory; Absent removes its matching exclusion. This reduces scanning for that path, without installing or validating any tool.'
        Requirements = @('Existing Windows 11 declaration only; no broader target support inferred from references. RIDE does not restart, upload samples or refresh the GUI.', 'Requires elevated Defender cmdlets and an observable exclusion list; managed or hidden exclusions can make local membership incomplete. The configured tools path is resolved at capture; tamper/management rejection remains visible.')
        OtherSupportedChoices = @('Saved restore owns exclusion membership at the captured path only. Created folders and their contents remain; no directory deletion or whole-list replacement. Both exclusion IDs remain in the default profile; inclusion is not new security acceptance.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Executing account Downloads/bootstrap Defender Antivirus scan exclusion'
        Behavior = 'Configuration'
        GuiPath = 'Windows Security > Virus & threat protection > Manage settings > Exclusions'
        GuiEffect = 'Present may create Downloads/bootstrap and add its scan exclusion; Absent removes its matching exclusion. The directory belongs to the executing account, which may differ when elevated with another account.'
        Requirements = @('Existing Windows 11 declaration only; no broader target support inferred from references. RIDE does not restart, upload samples or refresh the GUI.', 'Requires elevated Defender cmdlets, intended-account Downloads resolution and visible exclusion membership. Managed/tamper/hidden exclusions need separate verification; this is not an exemption from other protection layers.')
        OtherSupportedChoices = @('Saved restore uses the captured resolved path and recovers exclusion membership only; it does not delete the created directory or downloaded content. Separate identity/default-profile acceptance remains open.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus')
      }
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
      Description = 'Control the LLMNR DNS-client policy. Disabled writes EnableMulticast=0; Enabled removes the override. The legacy DisableMulticastDNS name was misleading: this setting does not disable mDNS, NetBIOS or all multicast traffic. Effective policy and dependent name resolution require separate verification.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient#turn_off_multicast'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Link-Local Multicast Name Resolution'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution'
        GuiEffect = 'Disabled writes EnableMulticast=0; published Enabled removes the policy value. The policy addresses LLMNR, not multicast DNS (mDNS) or every fallback name-resolution protocol.'
        Requirements = @('Microsoft documents this policy mapping for DNS clients. Verify applicable edition, policy precedence and dependent name resolution; no adapter/DNS server is configured.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy DisableMulticastDNS and the later LLMNR selectors duplicate this LLMNR value despite the former name. Enable/Baseline/unset remove the override; no explicit allow value is offered.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient#turn_off_multicast')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#allowlocation'
      SettingPresentation = @{
        AppliesTo = 'All users on this device: Windows location feature policy'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Settings > Privacy & security > Location; Group Policy > Computer Configuration > Administrative Templates > Windows Components > Location and Sensors > Turn off location'
        GuiEffect = 'Disabled writes DisableLocation=1 to block the Windows location feature. Enabled, Baseline and unset remove this machine override; they do not force location or app consent on. Location controls may be restricted by policy; current registry-to-UI and managed-precedence evidence remains open.'
        Requirements = @('Administrator privileges. Microsoft maps the device Turn off location policy on Pro, Enterprise, Education and IoT Enterprise; current build/edition and location-provider availability must be checked.', 'Apps using Windows location may lose location-dependent functions. Other methods such as IP-derived location are outside this policy. Removing policy does not grant individual app permission or restore past location data.')
        OtherSupportedChoices = @('Native user/app location permissions and separately scoped user policy remain independent. RIDE implements this machine restriction only; CSP Force Location On is not a state here.', 'Location scripting is a separate advanced legacy policy. The legacy DisableLocation bundle wrote both policies and its reverse removed both; this operation owns only DisableLocation.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#allowlocation', 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-sensors#disablelocationscripting_2')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-sensors#disablelocationscripting_2'
      SettingPresentation = @{
        AppliesTo = 'All users on this device: advanced legacy location-scripting policy'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Group Policy > Computer Configuration > Administrative Templates > Windows Components > Location and Sensors > Turn off location scripting'
        GuiEffect = 'Disabled writes DisableLocationScripting=1; Enabled, Baseline and unset remove the override. Microsoft describes blocking scripts for the location feature. A current Windows 11 consumer and visible effect are unverified; no modern browser-wide geolocation or script-blocking benefit is claimed.'
        Requirements = @('Administrator privileges. The device ADMX policy lists Pro, Enterprise, Education and IoT Enterprise on Windows 11; template presence does not prove an active consumer.', 'Location-feature availability and app/browser-specific permissions are separate dependencies. The existing default profile selects this advanced legacy ID; recommendation review remains open until current-build consumer behavior is established.')
        OtherSupportedChoices = @('The location-service policy is the normal feature-level control. Individual app and browser geolocation permissions are independent and are not configured here.', 'The legacy location bundle wrote both values and removed both on reverse. This ID preserves independent literal capture/restore; removal is not an explicit permissive policy write.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-sensors#disablelocationscripting_2', 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#allowlocation')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#disableadvertisingid'
      SettingPresentation = @{
        AppliesTo = 'All users on this device: Windows advertising ID policy'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Group Policy > Computer Configuration > Administrative Templates > System > User Profiles > Turn off the advertising ID; related Windows privacy controls vary by build'
        GuiEffect = 'Disabled writes DisabledByGroupPolicy=1 to prevent apps using the Windows advertising ID. Enabled, Baseline and unset remove the machine restriction so user choice can apply; they do not force the ID on. Native UI policy indication and refresh remain acceptance items.'
        Requirements = @('Administrator privileges. Microsoft documents this device policy for Pro, Enterprise, Education and IoT Enterprise; exact edition/build and managed-source precedence need acceptance.', 'This controls one Windows identifier, not all advertising, cookies, browser profiles, telemetry or personalization. It requires no account enrollment for the local registry action.')
        OtherSupportedChoices = @('Native user choice is separate from machine enforcement. RIDE does not reset or capture the identifier itself.', 'Saved restore recovers the prior policy value/type/absence; it does not recover a former advertising identifier or app-side personalization data.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#disableadvertisingid')
      }
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
      Name = 'Legacy Windows Update wake request (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System'
      Description = 'Retain the historical AUPowerManagement value at WindowsUpdate/AU. Current template mapping differs and Windows 11 behavior is unverified. This operation does not configure the separate documented Automatic Maintenance WakeUp policy.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/deployment/update/avoid-legacy-policy-configurations'
      SettingPresentation = @{
        AppliesTo = 'Device: Historical Windows Update wake request at the legacy AU subkey'
        Behavior = 'Unverified'
        GuiPath = 'No verified current GUI mapping for the legacy AU-subkey value; the current template exposes a different older-policy path'
        GuiEffect = 'Disabled writes AUPowerManagement=0 at WindowsUpdate/AU; Enabled removes it. Current Windows 11 wake behavior at this path is unverified; the stored value is not proof that maintenance wake is disabled. Baseline and unset remove the owned override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Administrator rights for the device write. RIDE does not refresh policy, restart, sign out, run updates or change services.', 'Local WindowsUpdate.admx maps AUPowerManagement at WindowsUpdate without AU and declares an older-release support range. The current AutomaticMaintenanceWakeUp policy uses Task Scheduler/Maintenance/WakeUp, another different path. Neither is silently substituted.')
        OtherSupportedChoices = @('Legacy DisableMaintenanceWakeUp wrote this value and the separate non-policy maintenance WakeUp value to 0; its reverse removed both. Preserve both prior captures and review each consumer separately.', 'Keep update offering, installation, restart, sign-in and wake outcomes separate. A registry round trip establishes stored state only.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/deployment/update/avoid-legacy-policy-configurations')
      }
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
      Name = 'Automatic maintenance wake preference (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / System'
      Description = 'Write or remove the historical non-policy maintenance WakeUp preference. The reference documents feature behavior, not this registry value; current GUI and actual wake effects remain unverified.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/taskschd/task-maintenence'
      SettingPresentation = @{
        AppliesTo = 'Device: Historical automatic-maintenance wake preference'
        Behavior = 'Unverified'
        GuiPath = 'Related: Control Panel > System and Security > Security and Maintenance > Automatic Maintenance; exact value-to-control mapping remains unverified'
        GuiEffect = 'Disabled writes WakeUp=0 at the non-policy Schedule/Maintenance key; Enabled removes it. This does not disable all wake timers, scheduled tasks, firmware wake sources or Windows updates. Baseline and unset remove the owned override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Administrator rights for the device write. RIDE does not refresh policy, restart, sign out, run updates or change services.', 'Microsoft documents maintenance/wake prerequisites, not this registry mapping. Power-plan wake policy, task definitions, power source and hardware sleep model require separate evidence. The documented policy WakeUp lives under a different Task Scheduler policy key.')
        OtherSupportedChoices = @('This is the other member of the legacy maintenance-wake bundle. Enabled/Baseline/unset remove this value; no explicit allow, schedule, task or hardware configuration is invented.', 'Keep update offering, installation, restart, sign-in and wake outcomes separate. A registry round trip establishes stored state only.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/win32/taskschd/task-maintenence')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Notification Center visibility'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'User Configuration > Administrative Templates > Start Menu and Taskbar > Remove Notifications and Action Center'
        GuiEffect = 'Disabled writes DisableNotificationCenter=1; published Enabled removes the override. Banners are separate.'
        Requirements = @('Microsoft documents the mapping; applicable edition, managed policy and shell refresh need acceptance.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy DisableActionCenter also wrote ToastEnabled=0. This operation owns only the center policy; the two removal reverses remain separate.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-taskbar#disablenotificationcenter')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy notification-banner preference'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Settings > System > Notifications'
        GuiEffect = 'Disabled writes ToastEnabled=0; published Enabled removes it. This does not itself set Notification Center policy.'
        Requirements = @('The reference describes notifications, not this exact preference. App-specific settings, Do not disturb and managed policy can change the outcome.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy Disable/EnableActionCenter wrote 0/removed both values across two paths. Current separate operations preserve those literal choices without claiming the whole bundle.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/notifications-and-do-not-disturb-in-windows')
      }
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
      Name = 'Sign-in background acrylic blur policy'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Control the clear sign-in background policy. Disabled writes DisableAcrylicBackgroundOnLogon=1; published Enabled removes the override and leaves effective rendering to Windows and other settings. This is the sign-in background, not authentication or lock-screen availability.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-logon#disableacrylicbackgroundonlogon'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Sign-in background acrylic blur'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > System > Logon > Show clear logon background'
        GuiEffect = 'Disabled writes DisableAcrylicBackgroundOnLogon=1. Published Enabled removes the policy override; it does not force blur in every environment.'
        Requirements = @('Microsoft documents the exact policy mapping; installed Logon.admx confirms its machine scope and key/value. Actual rendering, accessibility and managed policy remain separate acceptance.', 'Retain current target declarations. No sign-out, lock, restart, shutdown or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy Disabled/Enabled write 1/remove, matching current behavior. Baseline and unset remove the override; the stable operation ID retains its historical lock-screen wording.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from Baseline and override removal.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-logon#disableacrylicbackgroundonlogon')
      }
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
      Description = 'Select a legacy taskbar search presentation value: Hidden=0, Icon=1, Box=2. Current Windows 11 labels/options may differ; Microsoft documents the UI rather than these numeric mappings. Search functionality, indexing and web results remain separate.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Taskbar search presentation'
        Behavior = 'Unverified'
        GuiPath = 'Settings > Personalization > Taskbar > Search'
        GuiEffect = 'Hidden writes SearchboxTaskbarMode=0, Icon=1 and Box=2. These published names retain legacy numeric mappings.'
        Requirements = @('Microsoft documents multiple visible choices, not these numeric values. Current builds include an icon-and-label option absent from this operation; compare UI before relying on Box=2.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy hide/icon/box selectors used 0/1/2. Hiding the taskbar control does not disable search, indexing or web results.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows')
      }
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
      Description = 'Write ShowTaskViewButton=0 to request a hidden button, or remove the preference with published Visible. This controls a taskbar button rather than disabling virtual desktops. Current visible behavior remains subject to shell/build acceptance.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Task View taskbar button'
        Behavior = 'Unverified'
        GuiPath = 'Settings > Personalization > Taskbar > Task view'
        GuiEffect = 'Hidden writes ShowTaskViewButton=0; published Visible removes the override rather than writing 1.'
        Requirements = @('The feature reference describes the button, not this mapping. Hiding it does not remove desktops or disable the keyboard shortcut.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy Hide/ShowTaskView and Disable/EnableTaskbarDesktops are aliases of the same write/removal pair.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows')
      }
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
      Description = 'Choose the legacy primary-display combining value: Never=2, WhenFull=1, Always removes the override. Current-build button/label behavior needs UI acceptance; the legacy bundle also changed secondary displays.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Primary-display taskbar button combining'
        Behavior = 'Unverified'
        GuiPath = 'Settings > Personalization > Taskbar > Taskbar behaviors'
        GuiEffect = 'Never writes TaskbarGlomLevel=2; WhenFull writes 1; published Always removes the value, not writes 0.'
        Requirements = @('The visible combining options depend on Windows build. Microsoft documents the UI, not this numeric mapping.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy combining selectors changed both primary and secondary values. This operation changes only the primary value; removal matches legacy Always.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows')
      }
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
      Description = 'Choose the legacy secondary-display combining value: Never=2, WhenFull=1, Always removes the override. Requires applicable secondary-taskbar configuration and visible acceptance; it does not enable taskbars on other displays.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Secondary-display taskbar button combining'
        Behavior = 'Unverified'
        GuiPath = 'Settings > Personalization > Taskbar > Taskbar behaviors; secondary-display options'
        GuiEffect = 'Never writes MMTaskbarGlomLevel=2; WhenFull writes 1; published Always removes the value, not writes 0.'
        Requirements = @('Requires relevant multi-display taskbar configuration; the reference describes the UI, not this numeric mapping.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy combining selectors changed both values. This operation changes only the secondary value; enabling secondary taskbars is separate.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows')
      }
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
      Name = 'Legacy People taskbar preference (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Retain the legacy PeopleBand=0/removal preference. Visible removes the override and cannot recreate a missing People feature. The linked People Bar policy does not document this local value; current Windows 11 effect is unverified.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy People taskbar preference'
        Behavior = 'Unverified'
        GuiPath = 'No verified current Windows 11 equivalent for PeopleBand'
        GuiEffect = 'Hidden writes PeopleBand=0; published Visible removes it. Neither proves a current People button exists.'
        Requirements = @('The linked People Bar policy is a different control from this legacy local value. Feature presence and current effect remain unverified.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy People selectors wrote 0/removed, matching the literal pair. Do not reinterpret this as a current Teams or contacts feature.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings')
      }
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
      Name = 'Legacy notification-area promotion control (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Write the legacy NoAutoTrayNotify=1 policy value or remove it with Automatic. Current Windows 11 system-tray behavior is unverified; this is not a guaranteed show-all-icons control. No per-app tray settings are changed.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy notification-area overflow policy'
        Behavior = 'Unverified'
        GuiPath = 'Related area: Settings > Personalization > Taskbar > System tray icons'
        GuiEffect = 'ShowAll writes NoAutoTrayNotify=1; Automatic removes it. Current Windows 11 overflow behavior is unverified.'
        Requirements = @('The background taskbar reference does not establish this value as a supported current show-all switch. Per-app visibility and system icons remain separate.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy Show/HideTrayIcons wrote 1/removed. Automatic is override removal, not a command to hide every icon.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Windows startup sound preference, shared across users'
        Behavior = 'Preference'
        GuiPath = 'Control Panel > Sound > Sounds > Play Windows Startup sound (related UI; current mapping needs acceptance)'
        GuiEffect = 'Enabled writes DisableStartupSound=0; Disabled writes 1. This changes only the stored machine preference. Actual startup playback and checkbox editability depend on applicable policy, audio availability and target acceptance.'
        Requirements = @(
          'Windows 11; administrator rights required for this machine registry value, independently of the privileges of the related GUI',
          'The themes reference documents sound personalization, not this registry value or startup checkbox. Boot, GUI and managed-policy behavior remain pending'
        )
        OtherSupportedChoices = @(
          'Baseline explicitly selects Enabled; it does not reproduce the catalog-declared absent literal default or prove effective playback',
          'No unset state is declared. Saved-run restore recovers the captured prior value, type or absence; sound-scheme selection and playback-device mute are separate'
        )
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/personalize-your-windows-experience-with-themes')
      }
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
      Description = 'Write TaskbarDa=0 for the legacy hidden-button preference, or remove it with Visible. This does not uninstall Widgets, disable the board or establish content/network policy. Current Windows 11 mapping remains unverified.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/stay-up-to-date-with-widgets-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Widgets taskbar button'
        Behavior = 'Unverified'
        GuiPath = 'Settings > Personalization > Taskbar > Widgets'
        GuiEffect = 'Hidden writes TaskbarDa=0; published Visible removes it. This is not a Widgets service or content policy.'
        Requirements = @('The reference documents button visibility, not this registry mapping. Feature/build/managed-policy behavior requires acceptance.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy Widgets selectors wrote 0/removed. Removing the preference does not force the button visible under another policy.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/stay-up-to-date-with-widgets-in-windows')
      }
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
      Name = 'Legacy Chat taskbar preference (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / User interface'
      Description = 'Retain TaskbarMn=0/removal for the original Windows 11 Chat button. Visible removes the override; it does not install Teams or recreate a removed Chat feature. Current taskbar effect remains unverified and app pins are separate.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy Windows 11 Chat button'
        Behavior = 'Unverified'
        GuiPath = 'No verified current replacement for the original Chat taskbar control'
        GuiEffect = 'Hidden writes TaskbarMn=0; published Visible removes it. Current Teams app pins are separate.'
        Requirements = @('The current taskbar reference does not establish an active Chat control or exact mapping on every Windows 11 build.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy Chat selectors wrote 0/removed. They did not install Teams; this operation cannot recreate a removed shell feature.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Seconds in the system-tray clock'
        Behavior = 'Unverified'
        GuiPath = 'Related feature: Windows date/time settings > system-tray clock seconds (location varies by build)'
        GuiEffect = 'Shown writes ShowSecondsInSystemClock=1; published Hidden removes the preference.'
        Requirements = @('Microsoft documents the visible seconds option, not this registry mapping. Build, power usage and actual clock rendering need acceptance.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy Show/HideSeconds used 1/removal. Hidden is override removal, not an explicit zero.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/set-time-date-and-time-zone-settings-in-windows')
      }
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
      Description = 'Choose the retained MultiTaskingAltTabFilter value: Excluded=3, RecentTabs=1, ThreeRecentTabs=2, AllRecentTabs=0. Legacy names do not guarantee current tab counts or an unlimited all-tabs mode. Verify the Multitasking UI on the selected build; application windows remain separate.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/how-to-multitask-in-windows-b4fa0333-98f8-ef43-e25c-06d4fb1d6960'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Browser tabs in the Alt+Tab switcher'
        Behavior = 'Unverified'
        GuiPath = 'Settings > System > Multitasking > tabs in Alt+Tab'
        GuiEffect = 'Excluded writes MultiTaskingAltTabFilter=3; RecentTabs=1, ThreeRecentTabs=2, AllRecentTabs=0.'
        Requirements = @('Names retain legacy meanings; the number of available tabs and supported apps vary by Windows build. The feature reference does not prove every numeric mapping.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy selectors intended none/five/three/all using 3/1/2/0. Current AllRecentTabs must not be read as an unlimited current-build guarantee.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/how-to-multitask-in-windows-b4fa0333-98f8-ef43-e25c-06d4fb1d6960')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: All desktop icons'
        Behavior = 'Preference'
        GuiPath = 'Desktop context menu > View > Show desktop icons'
        GuiEffect = 'Visible writes HideIcons=0; Hidden writes 1. This changes desktop display only; it does not remove files, shortcuts or the individual system-icon choices.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents the visible option, not this registry mapping. Verify current-user GUI behavior and policy interaction on the target.')
        OtherSupportedChoices = @('Legacy selectors wrote the same explicit 0/1. Baseline/unset writes Visible=0; exact saved restore may instead recover absence.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: hidden-file visibility in File Explorer'
        Behavior = 'Preference'
        GuiPath = 'File Explorer Options > View > Hidden files and folders'
        GuiEffect = 'Visible and Hidden are explicit preferences; protected operating system files have a separate visibility control'
        Requirements = @('Intended user with Windows 11 File Explorer; this ID does not require administrator rights', 'The reference explains hidden-file visibility, not the registry encoding; current GUI and managed precedence need acceptance')
        OtherSupportedChoices = @('Baseline Hidden is a RIDE choice; this ID does not declare a WindowsDefault state', 'No file attribute/permission changes, Explorer restart or automatic protected-file change; saved-run restore preserves prior type/data/absence')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/deployment/install-upgrade/find-lost-files-after-upgrading-windows')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Navigation-pane expansion to the current folder'
        Behavior = 'Preference'
        GuiPath = 'File Explorer Options > View > Navigation pane > Expand to open folder'
        GuiEffect = 'Enabled writes NavPaneExpandToCurrentFolder=1; the published Disabled state removes it and delegates to Windows and governing policy.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'The Microsoft settings schema documents the preference, not this registry mapping. The navigation pane must be visible; actual selection/expansion needs current-build acceptance.')
        OtherSupportedChoices = @('Legacy enable/remove semantics match. This does not enable Show all folders or pin Libraries; those remain independently useful controls.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: File Explorer sync-provider notification preference'
        Behavior = 'Preference'
        GuiPath = 'File Explorer Options > View > Show sync provider notifications; current GUI mapping requires acceptance'
        GuiEffect = 'Hidden writes ShowSyncProviderNotifications=0; the published Visible state removes the override. It does not stop synchronization, sign out a provider or disable all Windows notifications.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'The Microsoft link describes File Explorer behavior, not this registry value. Provider participation and current GUI rendering must be tested independently.')
        OtherSupportedChoices = @('Legacy Show wrote 1; current Visible removes the value instead. Retain this partial reverse distinction and the default-profile Hidden choice pending GUI/recommendation acceptance.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: recent file shortcuts in File Explorer Home'
        Behavior = 'Preference'
        GuiPath = 'File Explorer Options > General > Privacy > Show recently used files'
        GuiEffect = 'Hidden suppresses recent shortcuts; the published Visible state removes the ShowRecent override and delegates to Windows and applicable controls rather than explicitly forcing the switch on'
        Requirements = @('Intended user with Windows 11 File Explorer Home; this ID does not require administrator rights', 'The reference documents the preference surface, not the ShowRecent registry mapping; current GUI, policy interaction and actual history display need acceptance')
        OtherSupportedChoices = @('Frequent folders and recent-history policies remain separate; no history is cleared', 'Visible and saved-run restore differ; restore preserves the prior value type/data/absence and no shell refresh is forced')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/backup-recovery/windows-backup-settings-catalog')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: frequent folder shortcuts in File Explorer Home'
        Behavior = 'Preference'
        GuiPath = 'File Explorer Options > General > Privacy > Show frequently used folders'
        GuiEffect = 'Hidden suppresses frequent shortcuts; the published Visible state removes the ShowFrequent override and delegates to Windows and applicable controls rather than explicitly forcing the switch on'
        Requirements = @('Intended user with Windows 11 File Explorer Home; this ID does not require administrator rights', 'The reference documents the preference surface, not the ShowFrequent registry mapping; current GUI, policy interaction and actual history display need acceptance')
        OtherSupportedChoices = @('Recent files and history policies remain separate; no history is cleared', 'Visible and saved-run restore differ; restore preserves the prior value type/data/absence and no shell refresh is forced')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/backup-recovery/windows-backup-settings-catalog')
      }
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
      Description = 'Choose the current user File Explorer landing-page preference: This PC or Home (formerly Quick access). Microsoft documents the GUI choice, not numeric LaunchTo values. Home/baseline writes 2 rather than reproducing the legacy reverse removal. No history, pin, existing window or Explorer process is changed.'
      DocumentationUri = 'https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Landing page for a new File Explorer window'
        Behavior = 'Preference'
        GuiPath = 'File Explorer Options > General > Open File Explorer to'
        GuiEffect = 'ThisPC writes LaunchTo=1; Home writes 2. Home was named Quick access on earlier Windows 11 builds. This does not change pinned folders or clear recent/frequent history.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents the landing-page choice, not numeric LaunchTo mapping. Verify new-window behavior on the selected build; existing windows are not navigated or restarted.')
        OtherSupportedChoices = @('Legacy ThisPC wrote 1 but QuickAccess removed the override. Current Home and baseline/unset explicitly write 2. Other GUI locations are not assigned guessed numeric states.')
        ReferenceUris = @('https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows')
      }
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
      Name = 'Legacy thumbnail-cache request (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Retain the legacy DisableThumbnailCache value under Explorer/Advanced as an experimental request. The Microsoft Group Policy Preferences specification names the mapping, but current Windows cache behavior requires acceptance. Disabled writes 1; Enabled removes it. No cache is deleted.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy DisableThumbnailCache request'
        Behavior = 'Unverified'
        GuiPath = 'No verified current GUI equivalent for this legacy value'
        GuiEffect = 'Disabled writes DisableThumbnailCache=1; Enabled removes the value. The effect on current Windows thumbnail caches has not been established; this is not a cache-deletion command.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'The Group Policy Preferences specification names this exact legacy registry mapping. Its caching attribute description does not establish current Windows consumer behavior or polarity.')
        OtherSupportedChoices = @('Legacy writes/removal match. Default-profile Disabled remains unchanged with recommendation acceptance open; saved recovery restores the value, not generated or previously removed cache content.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f')
      }
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
      Name = 'Legacy network-thumbnail request (experimental)'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Retain the experimental legacy DisableThumbsDBOnNetworkFolders value under Explorer/Advanced. Microsoft documents the same value name at Software/Policies/Microsoft/Windows/Explorer instead; this operation does not implement that policy. Current network-cache effect is unverified. Disabled writes 1; Enabled removes the legacy value; no cache file is deleted.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-thumbnails#disablethumbsdbonnetworkfolders'
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: Legacy network-thumbnail value outside the documented policy path'
        Behavior = 'Unverified'
        GuiPath = 'No verified current GUI equivalent; related policy: File Explorer > Turn off the caching of thumbnails in hidden thumbs.db files'
        GuiEffect = 'Disabled writes DisableThumbsDBOnNetworkFolders=1 under Explorer/Advanced; Enabled removes it. This is not the registry path of the documented policy and must not be treated as proof that network caching is disabled.'
        Requirements = @('Existing Windows 11 declaration only; no target expansion. No forced GUI refresh, sign-out or restart.', 'Microsoft documents Software/Policies/Microsoft/Windows/Explorer instead. Current legacy-path consumer behavior remains unverified; no network share, database or policy is changed by inspection.')
        OtherSupportedChoices = @('Legacy writes/removal match the retained path. Do not silently remap this stable ID or its saved captures. Default-profile inclusion remains a recorded recommendation gap; a corrected policy needs a separate migration/recovery decision.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-thumbnails#disablethumbsdbonnetworkfolders')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Windows Server automatic administrative-share creation'
        Behavior = 'Configuration'
        GuiPath = 'Computer Management > Shared Folders > Shares shows results; no automatic service action'
        GuiEffect = 'Disabled writes AutoShareServer=0; Enabled removes it. The documented mechanism excludes IPC$ and manually created shares.'
        Requirements = @('Microsoft documents the server value and service restart requirement. A restart would interrupt sharing and is not performed by RIDE. Verify dependent administration and actual shares on the declared Server target.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('The legacy selector wrote both Server and Workstation values together; the target-specific operations split that scope. Reverse removes each override; saved restore does not restore an active session or deleted data.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/remove-administrative-shares')
      }
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
      Description = 'Retain the AutoShareWks configuration for workstation administrative-share creation. Disabled writes 0; Enabled removes the override. Microsoft names this exact value/path in Server-scoped troubleshooting; Windows 11 functional acceptance remains separate. No service restart, share deletion or SMB access change is directly invoked.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/problems-administrative-shares-missing'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Windows workstation automatic administrative-share creation'
        Behavior = 'Configuration'
        GuiPath = 'Computer Management > Shared Folders > Shares shows results; no automatic service action'
        GuiEffect = 'Disabled writes AutoShareWks=0; Enabled removes it. This does not disable the SMB service, revoke credentials or remove user-created shares.'
        Requirements = @('Microsoft names AutoShareWks and its path in administrative-share troubleshooting, though that article is Server-scoped. Actual Windows 11 behavior and restart requirements remain acceptance work.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('The legacy selector wrote this value alongside AutoShareServer. Reverse/Baseline/unset remove it; no new Server or workstation support is inferred from the reference.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/problems-administrative-shares-missing')
      }
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
      Description = 'Legacy writes bootmenupolicy=Legacy for the current boot entry. The published Standard state removes the override rather than explicitly writing Standard. Effective menu behavior requires restart acceptance; exact saved restore recovers the prior element and its existence.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#boot-settings'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Current boot entry F8 menu policy'
        Behavior = 'Configuration'
        GuiPath = 'No direct Settings switch; BCD bootmenupolicy'
        GuiEffect = 'Legacy writes bootmenupolicy=Legacy. Published Standard removes the element; it does not explicitly write Standard.'
        Requirements = @('Microsoft documents F8 behavior for Legacy and Standard. Its listed historical defaults do not establish every current target image; verify effective boot behavior on the declared Windows 11 target.', 'Use an isolated disposable target with independent recovery media and encrypted-volume access. Do not automatically disable Secure Boot or BitLocker or trigger restart.')
        OtherSupportedChoices = @('Legacy DisableF8BootMenu explicitly wrote Standard. The current published Standard reverse differs by removing the override; retain the stable state and exact saved recovery.', 'Saved-run restore recovers captured BCD value/existence; override removal does not prove the effective inherited policy.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#boot-settings')
      }
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
      Description = 'OptOut writes nx=OptOut for the current boot entry. The published OptIn state removes the override rather than explicitly writing OptIn. Effective DEP and application compatibility require isolated restart acceptance; application exceptions and other exploit protections are separate.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#verification-settings'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Current boot entry Data Execution Prevention policy'
        Behavior = 'Configuration'
        GuiPath = 'System Properties > Advanced > Performance > Data Execution Prevention is related; BCD nx is the owned value'
        GuiEffect = 'OptOut writes nx=OptOut. Published OptIn removes nx; it does not explicitly write OptIn.'
        Requirements = @('Microsoft documents the BCD choices. Hardware, process architecture and platform defaults affect effective DEP. No application exception list or exploit-protection configuration is owned.', 'Use an isolated disposable target with independent recovery media and encrypted-volume access. Do not automatically disable Secure Boot or BitLocker or trigger restart.')
        OtherSupportedChoices = @('Legacy SetDEPOptIn explicitly wrote OptIn; current OptIn removes the override instead. Baseline/unset share that removal. Keep saved restoration separate from a requested baseline.', 'Saved-run restore recovers captured BCD value/existence; override removal does not prove the effective inherited policy.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#verification-settings')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-systemservices#configuressdpdiscoveryservicestartupmode'
      SettingPresentation = @{
        AppliesTo = 'Machine service SSDPSRV; elevation required'
        Behavior = 'Configuration'
        GuiPath = 'Services (services.msc) > SSDPSRV > Properties > General; startup type and service status are separate'
        GuiEffect = 'Disabled stops and disables SSDP Discovery. Enabled selects Manual startup and starts or resumes the service now; it is not a restore to a stopped trigger-start observation.'
        Requirements = @('Review discovery consumers and service dependencies. The SystemServices policy reference documents startup modes, not live runtime or complete peer discovery; firewall and network profile remain separate.', 'Service must exist; dependencies, managed policy and transient states can prevent transitions. Existing supported targets are unchanged; no new GUI, boot or workload acceptance is claimed.')
        OtherSupportedChoices = @('Legacy EnableSSDPdiscovery selected Manual and started now, matching current Enabled intent. Manual startup permits demand start; a later trigger/runtime change is not a captured-state restore.', 'There is no unset/override-removal state. Restore the saved run for prior startup/runtime; an explicit preset or RIDE baseline is not a Windows default. Recovery does not undo effects in workloads or unowned dependencies.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-systemservices#configuressdpdiscoveryservicestartupmode')
      }
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
      Description = 'Set UPnP Device Host to Disabled/Stopped or Manual/Running. Enabled starts the service now, unlike the legacy enable selector that set Manual without starting. This controls the local hosting service; it does not configure a router, guarantee port forwarding, or enable every application UPnP client. Saved-run restore recovers the captured service state; there is no unset or startup-only Manual state for this ID.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-systemservices#configureupnpdevicehostservicestartupmode'
      SettingPresentation = @{
        AppliesTo = 'Machine service upnphost; elevation required'
        Behavior = 'Configuration'
        GuiPath = 'Services (services.msc) > upnphost > Properties > General; startup type and service status are separate'
        GuiEffect = 'Disabled stops and disables UPnP Device Host. Enabled selects Manual startup and starts or resumes it now. This does not configure router port forwarding or every application UPnP client.'
        Requirements = @('Review UPnP hosting and service dependencies. The Microsoft startup-policy reference does not prove active device hosting or current runtime behavior.', 'Service must exist; dependencies, managed policy and transient states can prevent transitions. Existing supported targets are unchanged; no new GUI, boot or workload acceptance is claimed.')
        OtherSupportedChoices = @('Legacy EnableUniversalPlugAndPlay set Manual but left Start-Service commented out. Current Enabled starts now and is not equivalent. A startup-only manual choice is not exposed by this ID; restore uses captured startup/runtime.', 'There is no unset/override-removal state. Restore the saved run for prior startup/runtime; an explicit preset or RIDE baseline is not a Windows default. Recovery does not undo effects in workloads or unowned dependencies.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-systemservices#configureupnpdevicehostservicestartupmode')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features#how-to-disable-wpad'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: WinHTTP proxy auto-discovery'
        Behavior = 'Configuration'
        GuiPath = 'Related Settings > Network & internet > Proxy auto-detection is separate'
        GuiEffect = 'Disabled writes DisableWpad=1; published Enabled removes it. This is the WinHTTP detection control, not the service startup setting or a universal application proxy switch.'
        Requirements = @('Microsoft documents the value and notes that direct DNS lookups and other applications can remain independent. A separately chosen proxy configuration may be necessary for connectivity.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy write/removal semantics match. Baseline/unset remove the override. The intended-user proxy observation/preparation contract remains separate; no service, PAC file or connection is changed.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features#how-to-disable-wpad')
      }
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
      Name = 'Remote Assistance request permission'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Network'
      Description = 'Allow or disallow users from requesting Remote Assistance by setting the documented fAllowToGetHelp behavior value; Quick Assist is managed separately.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-remoteassistance-exe-fallowtogethelp'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Local permission to request Windows Remote Assistance'
        Behavior = 'Configuration'
        GuiPath = 'System Properties > Remote > Remote Assistance; current GUI mapping requires acceptance'
        GuiEffect = 'Enabled writes fAllowToGetHelp=1; Disabled writes 0. This local setting is separate from managed assistance policy and the Quick Assist app.'
        Requirements = @('The Microsoft unattended-setting reference documents feature behavior, not this exact registry path. Available components, firewall, user consent and policy precedence remain prerequisites.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy selectors also added/removed an App.Support.QuickAssist capability. That component action is deliberately separate from this value; Store Quick Assist has its own reviewed lifecycle. Explicit 0/1 matches the legacy setting part.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-remoteassistance-exe-fallowtogethelp')
      }
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
      Description = 'Set the documented AllowMUUpdateService device preference for updates to other Microsoft products. Does not invoke the legacy Microsoft.Update.ServiceManager registration/removal calls; full service-enrollment equivalence remains unverified.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common'
      SettingPresentation = @{
        AppliesTo = 'Device: Receiving updates for other Microsoft products'
        Behavior = 'Preference'
        GuiPath = 'Settings > Windows Update > Advanced options > Receive updates for other Microsoft products'
        GuiEffect = 'Enabled writes AllowMUUpdateService=1; Disabled writes 0. This is the documented device preference; it does not itself query, register or remove an update service or start updating. Baseline and unset remove the owned override; saved-run restore recovers the captured value/type/absence.'
        Requirements = @('Administrator rights for the device write. RIDE does not refresh policy, restart, sign out, run updates or change services.', 'The reference maps this preference, not full Microsoft Update service enrollment or managed precedence. Current checkbox/service correlation and update availability need separate acceptance.')
        OtherSupportedChoices = @('Legacy EnableUpdateMSProducts/DisableUpdateMSProducts called Microsoft.Update.ServiceManager AddService2/RemoveService. Registry preference recovery is not service-registration recovery; the complete legacy service outcome remains partial.', 'Keep update offering, installation, restart, sign-in and wake outcomes separate. A registry round trip establishes stored state only.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > Application Experience > Microsoft Compatibility Appraiser'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Collects application compatibility information used in upgrade readiness. Disabling its schedule can affect compatibility assessment; this does not disable all diagnostic data. The reference documents the task API; the legacy identity is not a current feature guarantee.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableTelemetry/EnableTelemetry changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\Application Experience\ProgramDataUpdater; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > Application Experience > ProgramDataUpdater'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the existing ProgramDataUpdater task schedule. Its current payload is build-dependent; the cmdlet reference documents enablement, not a verified complete privacy outcome. The reference documents the task API; the legacy identity is not a current feature guarantee.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableTelemetry/EnableTelemetry changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\Autochk\Proxy; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > Autochk > Proxy'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the existing Autochk Proxy task schedule. This does not disable disk checking or prove suppression of every disk diagnostic. The reference documents the task API; the legacy identity is not a current feature guarantee.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableTelemetry/EnableTelemetry changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\Customer Experience Improvement Program\Consolidator; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > Customer Experience Improvement Program > Consolidator'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the existing CEIP Consolidator task schedule. Missing legacy tasks are unavailable; disabling this task does not disable Windows diagnostic-data policy. The reference documents the task API; the legacy identity is not a current feature guarantee.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableTelemetry/EnableTelemetry changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\Customer Experience Improvement Program\UsbCeip; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > Customer Experience Improvement Program > UsbCeip'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the existing UsbCeip task schedule. USB device operation and other diagnostic-data controls remain separate. The reference documents the task API; the legacy identity is not a current feature guarantee.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableTelemetry/EnableTelemetry changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > DiskDiagnostic > Microsoft-Windows-DiskDiagnosticDataCollector'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the existing disk diagnostic data collector schedule. This does not disable disk checking, repair or the diagnostic service. The reference documents the task API; the legacy identity is not a current feature guarantee.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableTelemetry/EnableTelemetry changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\Feedback\Siuf\DmClient; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > Feedback > Siuf > DmClient'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the schedule of the existing Feedback Siuf DmClient task. Availability and payload depend on the Windows build. Feedback notification policy and frequency remain separate; the API reference establishes task enablement, not complete suppression of feedback requests.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableFeedback/EnableFeedback changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > Feedback > Siuf > DmClientOnScenarioDownload'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the schedule of the existing Feedback Siuf DmClientOnScenarioDownload task. Its exact downloaded-scenario behavior remains build-dependent and unverified. This is separate from DmClient, notification policy and feedback frequency; the reference documents only the task API.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableFeedback/EnableFeedback changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\Windows Error Reporting\QueueReporting; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > Windows Error Reporting > QueueReporting'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls only the existing QueueReporting task schedule. Windows Error Reporting policy, service and application error-reporting behavior remain separate. The reference documents the task API.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableErrorReporting/EnableErrorReporting changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Windows\Defrag\ScheduledDefrag; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Windows > Defrag > ScheduledDefrag'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the existing ScheduledDefrag task schedule, including Windows drive optimization appropriate to the drive type. Disabling the schedule does not run optimization or change manual optimization. The reference documents the task API.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableDefragmentation/EnableDefragmentation changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Office\Office ClickToRun Service Monitor; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Office > Office ClickToRun Service Monitor'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the existing Office ClickToRun Service Monitor schedule. This is Office installation/service maintenance, so disabling it can affect maintenance rather than providing a general privacy outcome. It is unavailable without the matching task; the reference documents task enablement.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableTelemetry/EnableTelemetry changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Office\OfficeTelemetryAgentFallBack2016; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Office > OfficeTelemetryAgentFallBack2016'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the existing OfficeTelemetryAgentFallBack2016 task schedule. This identifies the fallback Office 2016 telemetry-agent task, not the logon task. Its current payload and installed-version applicability require acceptance; disabling it does not establish complete Office diagnostic-data suppression. The reference documents the task API.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableTelemetry/EnableTelemetry changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps'
      SettingPresentation = @{
        AppliesTo = 'Machine task \Microsoft\Office\OfficeTelemetryAgentLogOn2016; administrator rights required'
        Behavior = 'Configuration'
        GuiPath = 'Task Scheduler > Task Scheduler Library > Microsoft > Office > OfficeTelemetryAgentLogOn2016'
        GuiEffect = 'Disabled clears the existing task enablement flag; Enabled sets it. RIDE does not send a Start or Stop request, replace the definition, change triggers or remove history. Existing triggers can run an enabled task.'
        Requirements = @('The exact task and ScheduledTasks module must be available. Task actions, arguments, conditions, permissions and product/build applicability require review before activation. Missing tasks are unavailable; this ID does not create them.', 'Controls the existing OfficeTelemetryAgentLogOn2016 task schedule. This identifies the Office 2016 telemetry-agent logon task, separately from its fallback task. Missing tasks are unavailable; current payload and Office diagnostic-policy interaction require acceptance. The reference documents the task API.', 'Microsoft references document the enablement API, not a current-build guarantee for the task payload or a complete privacy/maintenance outcome. Existing supported-target declarations are unchanged.')
        OtherSupportedChoices = @('Legacy DisableTelemetry/EnableTelemetry changed this task enablement alongside any separately recorded bundle members. Current Enabled is explicit true, not a Windows default or saved prior state.', 'No unset, task deletion or definition rollback is exposed. Saved-run restore recovers only the captured enablement of the same existing identity; it cannot undo work already performed by a task.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps', 'https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Frequently used applications in Start'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > Start Menu and Taskbar > Remove frequent programs list from the Start Menu'
        GuiEffect = 'Hidden writes NoStartMenuMFUprogramsList=1; Allowed writes 0; WindowsDefault removes it.'
        Requirements = @('Microsoft documents the policy mapping. Usage tracking, other policies and current Start layout can still suppress the list.', 'No Explorer restart, sign-out, pin change or application launch occurs. Retain existing target declarations and verify actual UI separately.')
        OtherSupportedChoices = @('Legacy ShowMostUsedApps removed the override. WindowsDefault matches removal; Allowed=0 explicitly permits the list but does not populate it.', 'Exact saved restore recovers registry type/value/absence. Removing an override leaves the effective choice to Windows and other controls.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start#hidefrequentlyusedapps')
      }
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
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#interactivelogon_donotrequirectrlaltdel'
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Ctrl+Alt+Delete before interactive sign-in'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Local Security Policy > Local Policies > Security Options > Interactive logon: Do not require CTRL+ALT+DEL'
        GuiEffect = 'Required writes DisableCAD=0; NotRequired writes 1. The policy label has the opposite polarity to Required.'
        Requirements = @('Microsoft documents secure-attention behavior and policy polarity. Managed policy, credential providers and actual sign-in behavior require separate acceptance.', 'Retain current target declarations. No sign-out, lock, restart, shutdown or policy refresh is initiated.')
        OtherSupportedChoices = @('Legacy EnableCtrlAltDelLogin/DisableCtrlAltDelLogin match 0/1. WindowsDefault removes the override; recovery must preserve an independently usable sign-in path.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from Baseline and override removal.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#interactivelogon_donotrequirectrlaltdel')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Device: Microsoft Defender Controlled Folder Access mode'
        Behavior = 'Configuration'
        GuiPath = 'Windows Security > Virus & threat protection > Ransomware protection > Manage ransomware protection'
        GuiEffect = 'Enabled=1 blocks untrusted changes to protected folders; Audit=2 records relevant activity without that blocking; Disabled=0 turns this feature off. Does not add protected folders, allowed apps or scan exclusions.'
        Requirements = @('Existing Windows 11 declaration only; no broader target support inferred from references. RIDE does not restart, upload samples or refresh the GUI.', 'Requires operational compatible Defender Antivirus and elevation. Managed/tamper controls can reject or supersede the local preference; verify known test-app behavior and events on a disposable target.')
        OtherSupportedChoices = @('Legacy enable/disable used the explicit 1/0 modes; Audit is an existing additional choice. No baseline/unset is declared for this ID. Saved restore recovers only the captured literal mode and cannot reverse file modifications.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: NCSI active connectivity tests policy'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Computer Configuration > Administrative Templates > System > Internet Communication Management > Internet Communication settings > Turn off Windows Network Connectivity Status Indicator active tests'
        GuiEffect = 'Disabled writes NoActiveProbe=1; Enabled writes 0. These names describe active tests, so policy-label polarity is inverted.'
        Requirements = @('The exact registry switch is documented. The local EnableActiveProbing setting, policy precedence and app behavior need separate checks; no endpoint, passive polling or firewall change.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy Enable removed the policy override. WindowsDefault preserves removal; explicit Enabled=0 differs. This is independently addressable policy, not a complete network-detection outcome.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Machine, elevation required: Local incoming Remote Desktop connection permission'
        Behavior = 'Configuration'
        GuiPath = 'Settings > System > Remote Desktop'
        GuiEffect = 'Enabled writes fDenyTSConnections=0; Disabled writes 1. This is only the local connection-permission component.'
        Requirements = @('Microsoft documents Remote Desktop prerequisites. Supported host edition, running service, firewall access, allowed users and NLA are separate; Home cannot serve as an RDP host. No listener or remote access test is implied.', 'Retain existing target declarations only. No service restart, remote connection, credential use, network reconfiguration or shell refresh is performed.')
        OtherSupportedChoices = @('Legacy enable/disable also toggled RemoteDesktop* firewall rules. This operation owns no firewall rules or authentication changes. Exact 0/1 values match the setting part; WindowsDefault removes it instead.', 'Saved-run restore recovers captured registry type/value/absence; it is separate from applying Baseline or removing an override.')
        ReferenceUris = @('https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Current Windows execution user: registered event sound scheme and current event mappings'
        Behavior = 'Preference'
        GuiPath = 'Settings > System > Sound > More sound settings > Sounds > Sound Scheme'
        GuiEffect = 'NoneScheme selects the registered .None preset; WindowsDefaultScheme selects .Default. Existing event mappings are copied into .Current, including preset customizations. A customized .None can contain sounds; neither state mutes a playback device or changes startup sound.'
        Requirements = @(
          'Windows 11 intended user with existing sound-scheme registration and events; no administrator rights required. Missing preset event values become empty sound strings',
          'Microsoft documents event sound configuration, not this registry implementation. Sound-scheme editing policy, UI refresh and actual playback require separate acceptance'
        )
        OtherSupportedChoices = @(
          'WindowsDefaultScheme selects a registered preset, not a factory reset, platform-default detection or captured-state restore; no baseline or unset state is declared',
          'Saved-run restore recovers captured selector and event values, types and absence, preserving source presets and newly registered unrelated events'
        )
        ReferenceUris = @('https://support.microsoft.com/en-us/surface/audio/surface-sound-volume-and-audio-accessories')
      }
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
      SettingPresentation = @{
        AppliesTo = 'Whole device: Microsoft Edge background mode across browser profiles'
        Behavior = 'EnforcedPolicy'
        GuiPath = 'Microsoft Edge > Settings > System > Continue running background apps when Microsoft Edge is closed'
        GuiEffect = 'Enabled and Disabled configure the mandatory policy; WindowsDefault removes this local policy override so the user preference and other applicable management can determine behavior'
        Requirements = @('Administrator rights; installed Microsoft Edge 77 or later on Windows', 'No extra RIDE account or cloud subscription for this local policy; current effective source, locked GUI and process behavior need acceptance')
        OtherSupportedChoices = @('Microsoft also supports a recommended policy path; this ID retains its existing machine mandatory path only', 'Startup boost, Edge Update scheduling and existing processes remain separate; this operation does not terminate processes')
        ReferenceUris = @('https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/backgroundmodeenabled')
      }
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
      Id = 'package.wireshark'
      Name = 'Wireshark (Machine MSI candidate)'
      Kind = 'Package'
      Category = 'Software / Network'
      Description = 'Install the pinned official Wireshark 4.6.9 x64 MSI for all users with capture-file associations disabled. Npcap live-capture enrollment remains a separate interactive workflow; this MSI contains no Npcap or USBPcap installer. Default capture-file selection is separate. Pending disposable lifecycle, existing-installation, shared-runtime, association-preservation and application acceptance.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11', 'Windows Server 2025')
      RequiresDesktopExperience = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'wireshark'
      InstallerType = 'Msi'
      DisplayNamePattern = '^Wireshark(?:\s|$)'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://www.wireshark.org/download/win64/all-versions/Wireshark-4.6.9-x64.msi'
      PackageVersion = '4.6.9'
      AssetName = 'Wireshark-4.6.9-x64.msi'
      ExpectedSha256 = '1975dfc96581a9b674fda3f41ac1585963b4ba52ea9459f3b6d9cedfac3a7217'
      Architecture = 'x64'
      ProductUri = 'https://www.wireshark.org/'
      License = 'GNU General Public License version 2; bundled component licenses and notices'
      LicenseUri = 'https://gitlab.com/wireshark/wireshark/-/blob/v4.6.9/COPYING'
      InstallerArguments = '/qn /norestart WIRESHARK_FILE_EXTENSIONS=0'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      Rollback = 'Compensating'
      DefaultVariant = 'installed'
      Variants = @{ installed = @{} }
      MigrationBatch = 'ApplicationsBatch1'
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
      Id = 'package.psscripttools'
      Name = 'PSScriptTools (Pinned source candidate)'
      Kind = 'Package'
      Category = 'Software / Utilities'
      Description = 'Stage the complete pinned PSScriptTools 3.2.0 repository source and MIT notices under Tools without importing the module, registering it on PSModulePath, modifying profiles or installing dependencies. Upstream import loads functions, format/type data, global variables and optional editor integration. Microsoft.PowerShell.Threadjob and System.Drawing remain separate runtime requirements. Source snapshot versus editable Git/Gallery deployment choice and native/runtime acceptance remain pending.'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'psscripttools'
      InstallerType = 'Portable'
      DisplayNamePattern = '^psscripttools$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/jdhitsolutions/PSScriptTools/archive/549fa3e3d769532320054fc0b3c8f42df0452361.zip'
      AssetName = 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361.zip'
      PackageVersion = '3.2.0-549fa3e3d769'
      ExpectedSha256 = '05c86295a0846ae4f51ecfa6f38ef71ba8173be83eb0adc8627525a4c6ee72bd'
      Architecture = 'neutral'
      ProductUri = 'https://github.com/jdhitsolutions/PSScriptTools'
      License = 'MIT; retain JDH Information Technology Solutions copyright and complete upstream notices'
      LicenseUri = 'https://github.com/jdhitsolutions/PSScriptTools/blob/549fa3e3d769532320054fc0b3c8f42df0452361/license.txt'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'IndividualPortableReview'
      PortableFormat = 'Zip'
      RequiredFiles = @('PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/PSScriptTools.psd1', 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/PSScriptTools.psm1', 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/license.txt', 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/README.md', 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/PSScriptToolsManual.pdf', 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/PSScriptToolData.json', 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/psansifilemap.json', 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/types/pstypemember.types.ps1xml', 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/types/PSScriptTools.type.ps1xml', 'PSScriptTools-549fa3e3d769532320054fc0b3c8f42df0452361/formats/psscripttool.format.ps1xml')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.hex2text'
      Name = 'Hex2text (Pinned Python source)'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Stage the pinned upstream script, README and GPL license without running code or installing Python. The script prompts for hexadecimal text, strips literal spaces and converts complete four-hex-digit groups to characters; it is not a general byte-to-UTF-8 decoder and ignores incomplete trailing groups. Python 3 syntax checked; runtime, input handling and native file-lifecycle acceptance remain pending.'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'hex2text'
      InstallerType = 'Portable'
      DisplayNamePattern = '^hex2text$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/gh05t-4/hex2text/archive/9715c6c26824ef05039228f16e0c47620c52fe79.zip'
      AssetName = 'hex2text-9715c6c26824ef05039228f16e0c47620c52fe79.zip'
      PackageVersion = 'source-9715c6c26824'
      ExpectedSha256 = 'aa0083da094a3320db9a97eb22c499a420187c208ed92376a662243678f083c3'
      Architecture = 'neutral'
      ProductUri = 'https://github.com/gh05t-4/hex2text'
      License = 'GNU GPL version 3; retain complete upstream source and license'
      LicenseUri = 'https://github.com/gh05t-4/hex2text/blob/9715c6c26824ef05039228f16e0c47620c52fe79/LICENSE'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'IndividualPortableReview'
      PortableFormat = 'Zip'
      RequiredFiles = @('hex2text-9715c6c26824ef05039228f16e0c47620c52fe79/LICENSE', 'hex2text-9715c6c26824ef05039228f16e0c47620c52fe79/README.md', 'hex2text-9715c6c26824ef05039228f16e0c47620c52fe79/hex2text.py')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.chromeparser'
      Name = 'ChromeSyncParser (Pinned Python source)'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Stage the complete pinned ChromeSyncParser source with README and MIT license. Does not scan browser profiles, open SQLite databases, execute the parser, install Python or change associations. Uses Python standard-library sqlite3 and historical SyncData/metas assumptions; syntax compatibility does not establish modern Chrome support or forensic correctness. Runtime and disposable source-file lifecycle acceptance remain pending.'
      SupportedTargets = @()
      CandidateTargets = @('Windows 11')
      PendingAcceptance = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'chromeparser'
      InstallerType = 'Portable'
      DisplayNamePattern = '^chromeparser$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/marleyjaffe/ChromeSyncParser/archive/0f59c5702ffd03102c550ecc373ab4fefa6f810c.zip'
      AssetName = 'ChromeSyncParser-0f59c5702ffd03102c550ecc373ab4fefa6f810c.zip'
      PackageVersion = '1.00-0f59c5702ffd'
      ExpectedSha256 = '8dff59a48d3d6ab41cf8d39154a0e05cfda5df36a1b76180a70692762854da46'
      Architecture = 'neutral'
      ProductUri = 'https://github.com/marleyjaffe/ChromeSyncParser'
      License = 'MIT; retain upstream copyright and license'
      LicenseUri = 'https://github.com/marleyjaffe/ChromeSyncParser/blob/0f59c5702ffd03102c550ecc373ab4fefa6f810c/LICENSE'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'IndividualPortableReview'
      PortableFormat = 'Zip'
      RequiredFiles = @('ChromeSyncParser-0f59c5702ffd03102c550ecc373ab4fefa6f810c/ChromeParser.py', 'ChromeSyncParser-0f59c5702ffd03102c550ecc373ab4fefa6f810c/LICENSE', 'ChromeSyncParser-0f59c5702ffd03102c550ecc373ab4fefa6f810c/README.md')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.regripper'
      Name = 'RegRipper 3.0 (Pinned portable distribution)'
      Kind = 'Package'
      Category = 'Software / Forensics'
      Description = 'Stage the complete pinned upstream RegRipper 3.0 repository distribution, including x86 GUI/CLI executables, bundled Perl runtime DLL, plugins, profiles and notices. Does not run parsers, update plugins, install Perl/Python/YARA or change registry hives. Retains the legacy 3.0 product line; RegRipper 4.0 has different restricted terms and is not substituted. Pending runtime, parser and disposable file-lifecycle acceptance.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      RequiresDesktopExperience = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'regripper'
      InstallerType = 'Portable'
      DisplayNamePattern = '^RegRipper$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/keydet89/RegRipper3.0/archive/ec96dd4a6a5c3ea70d8fece9b47a374f83582335.zip'
      AssetName = 'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335.zip'
      PackageVersion = '3.0-ec96dd4a6a5c'
      ExpectedSha256 = 'a1a13f6742990ca413e1763b90176d22ed4a9d663c4b37cb3f66e46f296acb43'
      Architecture = 'x86'
      ProductUri = 'https://github.com/keydet89/RegRipper3.0'
      License = 'MIT project license; retain all upstream contributor and bundled runtime notices'
      LicenseUri = 'https://github.com/keydet89/RegRipper3.0/blob/ec96dd4a6a5c3ea70d8fece9b47a374f83582335/license.txt'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'IndividualPortableReview'
      PortableFormat = 'Zip'
      RequiredFiles = @(
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/rr.exe',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/rip.exe',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/p2x5124.dll',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/license.txt',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/license.md',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/README.md',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/plugins/all',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/plugins/ntuser',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/plugins/software',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/plugins/system',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/plugins/sam',
        'RegRipper3.0-ec96dd4a6a5c3ea70d8fece9b47a374f83582335/plugins/winver.pl'
      )
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.rufus'
      Name = 'Rufus (Portable x64)'
      Kind = 'Package'
      Category = 'Software / Utilities'
      Description = 'Stage the pinned official Rufus 4.15 x64 portable executable as rufusp.exe without launching it. Preserve user-created rufus.ini, logs and other files. Media creation, downloads initiated by Rufus, runtime registry changes and USB recovery are separate operator actions. Pending disposable-target file lifecycle and application acceptance.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      RequiresDesktopExperience = $true
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'rufus'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Rufus$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/pbatard/rufus/releases/download/v4.15/rufus-4.15p.exe'
      AssetName = 'rufus-4.15p.exe'
      PackageVersion = '4.15'
      ExpectedSha256 = '84c8a437f8af89257524478489e5c85f1edf25f761d299e2bcde46ac0afbe106'
      Architecture = 'x64'
      ProductUri = 'https://rufus.ie/en/'
      License = 'GNU General Public License version 3 or later; retain upstream notices'
      LicenseUri = 'https://www.gnu.org/licenses/gpl-3.0.html'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = 'RequestedV3Additions'
      PortableFormat = 'File'
      PortableFileName = 'rufusp.exe'
      RequiredFiles = @('rufusp.exe')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-suite'
      Name = 'Sysinternals Suite (reviewed portable snapshot)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the exact 164-member official Suite snapshot acquired on 2026-10-17, retaining notices and mixed x86/x64 payloads without executing tools. The snapshot label is a RIDE acquisition identity, not a publisher suite version. A changed upstream ZIP fails its pinned digest. Individual product selection, per-tool target/runtime acceptance and collection updates remain pending. This does not install drivers, accept interactive EULAs, activate Sysmon, create shortcuts or change PATH.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-suite'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals Suite$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
      AssetName = 'SysinternalsSuite.zip'
      PackageVersion = 'snapshot-20261017-e1e75de5'
      ExpectedSha256 = 'e1e75de5cdb12116b0a4eca83725dc7c7a1645266196025cbe5ca6c167161aed'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @(
        'accesschk.exe',
        'accesschk64.exe',
        'AccessEnum.exe',
        'AdExplorer.chm',
        'ADExplorer.exe',
        'ADExplorer64.exe',
        'ADInsight.chm',
        'ADInsight.exe',
        'ADInsight64.exe',
        'adrestore.exe',
        'adrestore64.exe',
        'Autologon.exe',
        'Autologon64.exe',
        'Cacheset.exe',
        'Cacheset64.exe',
        'Clockres.exe',
        'Clockres64.exe',
        'Contig.exe',
        'Contig64.exe',
        'CPUSTRES.EXE',
        'CPUSTRES64.EXE',
        'Dbgview.chm',
        'Desktops.exe',
        'Desktops64.exe',
        'Disk2vhd.chm',
        'disk2vhd.exe',
        'disk2vhd64.exe',
        'diskext.exe',
        'diskext64.exe',
        'Diskmon.exe',
        'Diskmon64.exe',
        'DiskView.exe',
        'DiskView64.exe',
        'du.exe',
        'du64.exe',
        'efsdump.exe',
        'FindLinks.exe',
        'FindLinks64.exe',
        'handle.exe',
        'handle64.exe',
        'hex2dec.exe',
        'hex2dec64.exe',
        'junction.exe',
        'junction64.exe',
        'ldmdump.exe',
        'LoadOrd.exe',
        'LoadOrd64.exe',
        'LoadOrdC.exe',
        'LoadOrdC64.exe',
        'logonsessions.exe',
        'logonsessions64.exe',
        'movefile.exe',
        'movefile64.exe',
        'ntfsinfo.exe',
        'ntfsinfo64.exe',
        'pendmoves.exe',
        'pendmoves64.exe',
        'portmon.exe',
        'procexp.chm',
        'procmon.chm',
        'PsExec.exe',
        'PsExec64.exe',
        'psfile.exe',
        'psfile64.exe',
        'pslist.exe',
        'pslist64.exe',
        'PsLoggedon.exe',
        'PsLoggedon64.exe',
        'psloglist.exe',
        'psloglist64.exe',
        'pspasswd.exe',
        'pspasswd64.exe',
        'PsService.exe',
        'PsService64.exe',
        'Pstools.chm',
        'psversion.txt',
        'readme.txt',
        'RegDelNull.exe',
        'RegDelNull64.exe',
        'regjump.exe',
        'ru.exe',
        'ru64.exe',
        'ShareEnum.exe',
        'ShareEnum64.exe',
        'ShellRunas.exe',
        'streams.exe',
        'streams64.exe',
        'strings.exe',
        'strings64.exe',
        'sync.exe',
        'sync64.exe',
        'tcpvcon.exe',
        'tcpvcon64.exe',
        'tcpview.chm',
        'tcpview.exe',
        'tcpview64.exe',
        'Testlimit.exe',
        'Testlimit64.exe',
        'Vmmap.chm',
        'vmmap.exe',
        'vmmap64.exe',
        'Volumeid.exe',
        'Volumeid64.exe',
        'whois.exe',
        'whois64.exe',
        'Winobj.exe',
        'Winobj64.exe',
        'ctrl2cap.exe',
        'sdelete.exe',
        'sdelete64.exe',
        'RAMMap.exe',
        'RAMMap64.exe',
        'autoruns.chm',
        'Autoruns.exe',
        'autorunsc.exe',
        'Autoruns64.exe',
        'autorunsc64.exe',
        'Dbgview.exe',
        'dbgview64.exe',
        'dbgviewcli.exe',
        'dbgviewcli64.exe',
        'livekd.exe',
        'livekd64.exe',
        'notmyfault.exe',
        'notmyfault64.exe',
        'notmyfaultc.exe',
        'notmyfaultc64.exe',
        'Coreinfo.exe',
        'Coreinfo64.exe',
        'CoreinfoEx.exe',
        'CoreinfoEx64.exe',
        'psping.exe',
        'psping64.exe',
        'pipelist.exe',
        'pipelist64.exe',
        'PsGetsid.exe',
        'PsGetsid64.exe',
        'PsInfo.exe',
        'PsInfo64.exe',
        'psshutdown.exe',
        'psshutdown64.exe',
        'pssuspend.exe',
        'pssuspend64.exe',
        'Sysmon.exe',
        'Sysmon64.exe',
        'procexp.exe',
        'procexp64.exe',
        'ZoomIt.exe',
        'ZoomIt64.exe',
        'Bginfo.exe',
        'Bginfo64.exe',
        'Listdlls.exe',
        'Listdlls64.exe',
        'procdump.exe',
        'procdump64.exe',
        'Procmon.exe',
        'Procmon64.exe',
        'pskill.exe',
        'pskill64.exe',
        'sigcheck.exe',
        'sigcheck64.exe',
        'RDCMan-x86.exe',
        'RDCMan.exe',
        'Eula.txt'
      )
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-process-explorer'
      Name = 'Sysinternals Process Explorer (portable)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the pinned official Process Explorer 17.2 archive and its notices in an independently owned product folder. This is a separate copy from Sysinternals Suite. Mixed x86/x64/ARM64 files are preserved as upstream archive content; they do not establish target support. No tool launch, EULA acceptance, driver activation, startup/task change, connection closure, upload, shortcut or PATH change is performed. Native acceptance remains pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-process-explorer'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals Process Explorer$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/ProcessExplorer.zip'
      AssetName = 'ProcessExplorer.zip'
      PackageVersion = '17.2'
      ExpectedSha256 = 'dab147316264b89ae46ae2ad7d8a94116848ef0b703bcac8de9ff22689ce9d51'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @('procexp.exe', 'procexp64.exe', 'procexp64a.exe', 'Eula.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-autoruns'
      Name = 'Sysinternals Autoruns (portable)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the pinned official Autoruns 14.3 archive and its notices in an independently owned product folder. This is a separate copy from Sysinternals Suite. Mixed x86/x64/ARM64 files are preserved as upstream archive content; they do not establish target support. No tool launch, EULA acceptance, driver activation, startup/task change, connection closure, upload, shortcut or PATH change is performed. Native acceptance remains pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-autoruns'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals Autoruns$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/Autoruns.zip'
      AssetName = 'Autoruns.zip'
      PackageVersion = '14.3'
      ExpectedSha256 = '7b3a8eed819f732a3e4c134aecaeaebb8d643a46490ccddb82cc8a1a745c4cf7'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @('Autoruns.exe', 'autorunsc.exe', 'Autoruns64.exe', 'autorunsc64.exe', 'Autoruns64a.exe', 'autorunsc64a.exe', 'Eula.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-tcpview'
      Name = 'Sysinternals TCPView (portable)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the pinned official TCPView 4.19 archive and its notices in an independently owned product folder. This is a separate copy from Sysinternals Suite. Mixed x86/x64/ARM64 files are preserved as upstream archive content; they do not establish target support. No tool launch, EULA acceptance, driver activation, startup/task change, connection closure, upload, shortcut or PATH change is performed. Native acceptance remains pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-tcpview'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals TCPView$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/TCPView.zip'
      AssetName = 'TCPView.zip'
      PackageVersion = '4.19'
      ExpectedSha256 = '4fc5ceba3e1b27ad95a24df35d094b454ec5f9478e12a8ca2b1b222705b9683b'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @('tcpview.exe', 'tcpview64.exe', 'tcpview64a.exe', 'tcpvcon.exe', 'tcpvcon64.exe', 'tcpvcon64a.exe', 'tcpview.chm', 'Eula.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-procmon'
      Name = 'Sysinternals Process Monitor (portable)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the pinned official Process Monitor 4.12 archive and its notices in an independently owned product folder. This is a separate copy from Sysinternals Suite. Mixed x86/x64/ARM64 files are preserved as upstream archive content; they do not establish target support. No tool launch, EULA acceptance, driver activation, trace collection, memory modification, disk imaging, volume mounting, encryption change, shortcut or PATH change is performed. Native acceptance remains pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-procmon'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals Process Monitor$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/ProcessMonitor.zip'
      AssetName = 'ProcessMonitor.zip'
      PackageVersion = '4.12'
      ExpectedSha256 = '477754bf299c9e5b311c5666f7a4a48dfdb21265eaa8f0cca70ef9d9552e3a10'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/procmon'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @('Procmon.exe', 'Procmon64.exe', 'Procmon64a.exe', 'Eula.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-rammap'
      Name = 'Sysinternals RAMMap (portable)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the pinned official RAMMap 1.63 archive and its notices in an independently owned product folder. This is a separate copy from Sysinternals Suite. Mixed x86/x64/ARM64 files are preserved as upstream archive content; they do not establish target support. No tool launch, EULA acceptance, driver activation, trace collection, memory modification, disk imaging, volume mounting, encryption change, shortcut or PATH change is performed. Native acceptance remains pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-rammap'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals RAMMap$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/RAMMap.zip'
      AssetName = 'RAMMap.zip'
      PackageVersion = '1.63'
      ExpectedSha256 = '6536a8107a3fb391e4443f2742366067341a7da50de89f99ca0b2390120dd0cc'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/rammap'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @('RAMMap.exe', 'RAMMap64.exe', 'RAMMap64a.exe', 'Eula.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-disk2vhd'
      Name = 'Sysinternals Disk2vhd (portable)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the pinned official Disk2vhd 2.02 archive and its notices in an independently owned product folder. This is a separate copy from Sysinternals Suite. Mixed x86/x64/ARM64 files are preserved as upstream archive content; they do not establish target support. No tool launch, EULA acceptance, driver activation, trace collection, memory modification, disk imaging, volume mounting, encryption change, shortcut or PATH change is performed. Native acceptance remains pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-disk2vhd'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals Disk2vhd$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/Disk2vhd.zip'
      AssetName = 'Disk2vhd.zip'
      PackageVersion = '2.02'
      ExpectedSha256 = 'c294d279bf98645f84452989f320b561bf58609e35d85de47ea19ef583880821'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/disk2vhd'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @('disk2vhd.exe', 'Disk2vhd.chm', 'disk2vhd64.exe', 'disk2vhd64a.exe', 'Eula.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-sigcheck'
      Name = 'Sysinternals Sigcheck (portable)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the pinned official Sigcheck 2.93 archive and its notices in an independently owned product folder. This is a separate copy from Sysinternals Suite. Mixed x86/x64/ARM64 files are preserved as upstream archive content; they do not establish target support. No tool launch, EULA acceptance, driver activation, file scan, handle enumeration or closure, certificate-store change, remote lookup, upload, shortcut or PATH change is performed. Native acceptance remains pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-sigcheck'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals Sigcheck$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/Sigcheck.zip'
      AssetName = 'Sigcheck.zip'
      PackageVersion = '2.93'
      ExpectedSha256 = '8756099c1ce3d3f450245c0d4b39aeb5b29309f56bf77f8c18f1469c418abf12'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @('sigcheck.exe', 'sigcheck64.exe', 'sigcheck64a.exe', 'Eula.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-strings'
      Name = 'Sysinternals Strings (portable)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the pinned official Strings 2.54 archive and its notices in an independently owned product folder. This is a separate copy from Sysinternals Suite. Mixed x86/x64/ARM64 files are preserved as upstream archive content; they do not establish target support. No tool launch, EULA acceptance, driver activation, file scan, handle enumeration or closure, certificate-store change, remote lookup, upload, shortcut or PATH change is performed. Native acceptance remains pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-strings'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals Strings$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/Strings.zip'
      AssetName = 'Strings.zip'
      PackageVersion = '2.54'
      ExpectedSha256 = 'b1a0a3dc5f639af1c98ae5832676727646eb3d543640e65e310dff747e733a25'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/strings'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @('strings.exe', 'strings64.exe', 'strings64a.exe', 'Eula.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
    }
    @{
      Id = 'package.sysinternals-handle'
      Name = 'Sysinternals Handle (portable)'
      Kind = 'Package'
      Category = 'Software / System utilities'
      Description = 'Stage the pinned official Handle 5.0 archive and its notices in an independently owned product folder. This is a separate copy from Sysinternals Suite. Mixed x86/x64/ARM64 files are preserved as upstream archive content; they do not establish target support. No tool launch, EULA acceptance, driver activation, file scan, handle enumeration or closure, certificate-store change, remote lookup, upload, shortcut or PATH change is performed. Native acceptance remains pending.'
      SupportedTargets = @()
      PendingAcceptance = $true
      CandidateTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      TargetDefaults = @{}
      PackageId = 'sysinternals-handle'
      InstallerType = 'Portable'
      DisplayNamePattern = '^Sysinternals Handle$'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://download.sysinternals.com/files/Handle.zip'
      AssetName = 'Handle.zip'
      PackageVersion = '5.0'
      ExpectedSha256 = '279aaf8eccb6f79147f4dcc6ba091fb895c4cb8b199a0dd186a4c76bc519d2cd'
      Architecture = 'neutral'
      ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/handle'
      License = 'Proprietary - Microsoft Sysinternals Software License Terms; retain Eula.txt and upstream notices'
      LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
      InstallerArguments = ''
      UninstallerArguments = ''
      Rollback = 'Exact'
      MigrationBatch = '2026-10-17-reviewed-collections'
      PortableFormat = 'Zip'
      RequiredFiles = @('handle.exe', 'handle64.exe', 'handle64a.exe', 'Eula.txt')
      DefaultVariant = 'portable'
      Variants = @{ portable = @{} }
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
      Id = 'solution.store-gaming'
      Name = 'Xbox and gaming Store apps (experimental)'
      Category = 'Windows components / Store app groups'
      Description = 'Optional batch 3 intended-user app actions with per-app partial results and retained-source best-effort registration. Inspect actual dependencies/consumers before changes; shared frameworks and protected components stay guarded. Reverse member order for uninstall. Device policy stays separate; no default profile selection or package acquisition.'
      Workflow = 'StoreApps'
      Members = @('app.xbox-tcui', 'app.xbox-identity-provider', 'app.xbox-speech-overlay', 'app.xbox', 'app.game-bar')
      Actions = @('Uninstall', 'Reinstall')
      Rollback = 'BestEffort'
    }
    @{
      Id = 'solution.store-productivity'
      Name = 'Assistance and personal productivity Store apps (experimental)'
      Category = 'Windows components / Store app groups'
      Description = 'Optional batch 2C intended-user app actions with per-app partial results and retained-source best-effort registration. Inspect actual dependencies/consumers before changes; shared frameworks and protected components stay guarded. Reverse member order for uninstall. Device policy stays separate; no default profile selection or package acquisition.'
      Workflow = 'StoreApps'
      Members = @('app.quick-assist', 'app.sticky-notes', 'app.outlook', 'app.todo')
      Actions = @('Uninstall', 'Reinstall')
      Rollback = 'BestEffort'
    }
    @{
      Id = 'solution.store-multimedia'
      Name = 'Multimedia Store apps (experimental)'
      Category = 'Windows components / Store app groups'
      Description = 'Optional batch 2B intended-user app actions with per-app partial results and retained-source best-effort registration. Inspect actual dependencies/consumers before changes; shared frameworks and protected components stay guarded. Reverse member order for uninstall. Device policy stays separate; no default profile selection or package acquisition.'
      Workflow = 'StoreApps'
      Members = @('app.photos', 'app.paint', 'app.camera', 'app.media-player', 'app.sound-recorder')
      Actions = @('Uninstall', 'Reinstall')
      Rollback = 'BestEffort'
    }
    @{
      Id = 'solution.store-core-utilities'
      Name = 'Core utilities Store apps (experimental)'
      Category = 'Windows components / Store app groups'
      Description = 'Optional batch 2A intended-user app actions with per-app partial results and retained-source best-effort registration. Inspect actual dependencies/consumers before changes; shared frameworks and protected components stay guarded. Reverse member order for uninstall. Device policy stays separate; no default profile selection or package acquisition.'
      Workflow = 'StoreApps'
      Members = @('app.calculator', 'app.notepad', 'app.snipping-tool', 'app.terminal')
      Actions = @('Uninstall', 'Reinstall')
      Rollback = 'BestEffort'
    }
    @{
      Id = 'solution.store-consumer-apps'
      Name = 'Consumer Store apps (experimental)'
      Category = 'Windows components / Store app groups'
      Description = 'Optional Clipchamp, News, Weather and Solitaire registration actions; per-app results and source-bound best-effort reinstall. Uninstall uses reverse member order. Device policy is a separate workflow; this group downloads nothing and is excluded from profiles pending lifecycle acceptance.'
      Workflow = 'StoreApps'
      Members = @('app.clipchamp', 'app.news', 'app.weather', 'app.solitaire')
      Actions = @('Uninstall', 'Reinstall')
      Rollback = 'BestEffort'
    }
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
