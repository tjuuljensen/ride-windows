@{
  SchemaVersion = 1
  Operations = @(
    @{
      Id = 'windows.show-known-extensions'
      Name = 'Show known file extensions'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Explorer'
      Description = 'Show file extensions for registered file types in File Explorer.'
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
      InstallerArguments = '/S'
      UninstallerArguments = '/S'
      Rollback = 'Compensating'
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
