# Authoring example owned by RIDE-Windows maintainers. VM acceptance is pending.
# References checked against the publisher's download page on 2026-10-10.
# Requires the publisher's MSVC Redistributable prerequisite; this definition
# does not install that prerequisite. ProductUri is intentionally omitted.
@{
  Id = 'example.password-tools'
  Version = '0.1.0'
  Operations = @(
    @{
      Id = 'keepassxc'
      Kind = 'Package'
      Name = 'KeePassXC'
      Description = 'Example pinned 64-bit KeePassXC MSI. Requires the publisher-listed MSVC Redistributable; review prerequisites and test in a disposable Windows 11 VM.'
      Scope = 'Machine'
      SupportedTargets = @('Windows 11')
      InstallerType = 'Msi'
      Architecture = 'x64'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://github.com/keepassxreboot/keepassxc/releases/download/2.7.12/KeePassXC-2.7.12-Win64.msi'
      PackageVersion = '2.7.12'
      AssetName = 'KeePassXC-2.7.12-Win64.msi'
      DisplayNamePattern = '^KeePassXC(?:\s.*)?$'
      InstallerArguments = '/qn /norestart'
      UninstallerArguments = '/qn /norestart'
      SuccessExitCodes = @(0, 3010)
      License = 'GPL-2.0-only OR GPL-3.0-only; bundled components retain their own notices'
      LicenseUri = 'https://github.com/keepassxreboot/keepassxc/blob/develop/COPYING'
      RecoveryUri = 'https://keepassxc.org/download/'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Author-declared absent default; verify the target VM image' }
      }
    }
  )
}
