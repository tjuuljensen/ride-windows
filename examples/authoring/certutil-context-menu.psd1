# Authoring example owned by RIDE-Windows maintainers. VM acceptance is pending.
# Corrects the supplied icon declaration: Icon is the name, resource is the data.
# HKCR is converted to HKCU\Software\Classes because this example selects User.
# Change Scope to Machine for HKLM\Software\Classes and required elevation.
@{
  Id = 'example.context-menu'
  Version = '0.1.2'
  Operations = @(
    @{
      Id = 'sha256-certutil'
      Kind = 'RegistryValueSet'
      Name = 'SHA-256 with Certutil context menu'
      Description = 'Adds an all-files SHA-256 shortcut-menu verb with an icon and Certutil command. Test icon rendering, menu visibility, hashing and saved-run restore in a disposable Windows 11 VM.'
      Scope = 'User'
      SupportedTargets = @('Windows 11')
      RegistryValues = @(
        @{ Key = 'Menu'; RegistryPath = 'HKEY_CLASSES_ROOT\*\shell\SHA-256 with Certutil'; ValueName = 'Icon'; ValueType = 'String' }
        @{ Key = 'Command'; RegistryPath = 'HKEY_CLASSES_ROOT\*\shell\SHA-256 with Certutil\command'; ValueName = ''; ValueType = 'String' }
      )
      States = @{
        Enabled = @{ Menu = 'shell32.dll,-152'; Command = 'cmd.exe /k certutil -hashfile "%1" SHA256' }
        WindowsDefault = @{ Menu = $null; Command = $null }
      }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Custom context-menu registration; literal image defaults and menu behavior require VM verification.' }
      }
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/context-menu-handlers'
    }
  )
}
