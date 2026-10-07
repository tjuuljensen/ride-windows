@{
  SchemaVersion = 1
  Name = 'Default workstation'
  Description = 'A small starter configuration for a new Windows workstation.'
  Operations = @(
    @{ Id = 'windows.show-known-extensions'; State = 'Enabled' }
    @{ Id = 'windows.autoplay-policy'; State = 'Disabled' }
    @{ Id = 'windows.autorun-policy'; State = 'Disabled' }
    @{ Id = 'package.7zip'; State = 'Present' }
  )
}
