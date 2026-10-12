# Example metadata, not a Windows baseline. Owner: RIDE-Windows maintainers.
@{
  SchemaVersion = 1
  Operations = @(
    @{
      Id = 'example.contoso.preference-marker'
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
  )
  Groups = @(
    @{
      Id = 'example.contoso.utilities'
      Name = 'Example organization utilities'
      Category = 'Software / Library examples'
      Description = 'Reuse the existing 7-Zip product operation rather than creating a duplicate package definition.'
      Members = @('package.7zip')
      Actions = @('Install', 'Uninstall')
      Rollback = 'Compensating'
    }
  )
}
