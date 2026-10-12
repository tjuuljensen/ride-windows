# Main library example, not a Windows baseline. VM acceptance is pending.
# Readable formatting; helper-generated catalogs use the same schema.
@{
  SchemaVersion = 1
  Operations = @(
    @{
      Id = 'example.library.preference-marker'
      Name = 'Example organization preference marker'
      Kind = 'RegistryValue'
      Category = 'Windows settings / Library examples'
      Description = 'An inert organization marker under HKCU used to demonstrate external metadata and exact restore. It does not configure a Windows feature. The Microsoft reference documents registry value storage, not a Windows preference mapping.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValue'
      RegistryPath = 'HKCU:\Software\RIDE\Examples\Contoso'
      ValueName = 'PreferenceMarker'
      ValueType = 'DWord'
      States = @{ Enabled = 1; Disabled = 0; WindowsDefault = $null }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'No example organization marker; this is not a native Windows preference' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'example.library.sha256-certutil'
      Name = 'SHA-256 with Certutil context menu'
      Kind = 'RegistryValueSet'
      Category = 'Windows settings / Custom library'
      Description = 'Adds an all-files SHA-256 shortcut-menu verb with an icon and Certutil command. Test icon rendering, menu visibility, hashing and saved-run restore in a disposable Windows 11 VM.'
      DocumentationUri = 'https://learn.microsoft.com/en-us/windows/win32/shell/context-menu-handlers'
      SupportedTargets = @('Windows 11')
      Scope = 'User'
      RequiresAdmin = $false
      Actions = @('Get', 'Test', 'Set', 'Restore')
      Handler = 'RegistryValueSet'
      RegistryValues = @(
        @{ Key = 'Menu'; RegistryPath = 'HKCU:\Software\Classes\*\shell\SHA-256 with Certutil'; ValueName = 'Icon'; ValueType = 'String' }
        @{ Key = 'Command'; RegistryPath = 'HKCU:\Software\Classes\*\shell\SHA-256 with Certutil\command'; ValueName = ''; ValueType = 'String' }
      )
      States = @{
        Enabled = @{ Menu = 'shell32.dll,-152'; Command = 'cmd.exe /k certutil -hashfile "%1" SHA256' }
        WindowsDefault = @{ Menu = $null; Command = $null }
      }
      BaselineState = 'WindowsDefault'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = 'Custom context-menu registration; literal image defaults and menu behavior require VM verification.' }
      }
      Rollback = 'Exact'
    }
    @{
      Id = 'example.library.classic-msgames'
      Name = 'Windows 7 Games for Windows 11, 10 and 8'
      Kind = 'Package'
      Category = 'Software / Custom library'
      Description = 'Installs Solitaire, Spider Solitaire, Minesweeper, FreeCell, Hearts, Chess Titans, Mahjong Titans, Purble Place, Internet Spades, Internet Checkers, and Internet Backgammon'
      ProductUri = 'https://winaero.com/download-windows-7-games-for-windows-11/'
      SupportedTargets = @('Windows 11')
      Scope = 'Machine'
      RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      Handler = 'Package'
      PackageId = 'example.library.classic-msgames'
      InstallerType = 'Exe'
      ArchiveType = 'Zip'
      Architecture = 'x86'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://win7games.com/download/Windows7Games_for_Windows_11_10_8.zip'
      PackageVersion = '4.3'
      AssetName = 'Windows7Games_for_Windows_11_10_8.zip'
      ExpectedSha256 = 'b0db854664ba1b092e4f602dae9101130cb9a50cba103c9ef8b57362d7762b56'
      InstallerEntry = 'Windows 7 Games for Windows 11, 10 and 8-4.3-setup.exe'
      ExpectedInstallerSha256 = 'ae3ff402b459d4343d9fd0edf0d46186b9f604b2c989c9c8aa99adedfe4958ee'
      DisplayNamePattern = '^Solitaire$'
      InstallerArguments = ' /SP- /SILENT'
      UninstallerArguments = '/SILENT'
      License = 'Unknown'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Author-declared package default: Absent; verify the target image' }
      }
      Rollback = 'Compensating'
    }
  )
  Groups = @(
    @{
      Id = 'example.library.utilities'
      Name = 'Example organization utilities'
      Category = 'Software / Library examples'
      Description = 'Reuse the existing 7-Zip product operation rather than creating a duplicate package definition.'
      Members = @('package.7zip')
      Actions = @('Install', 'Uninstall')
      Rollback = 'Compensating'
    }
  )
}
