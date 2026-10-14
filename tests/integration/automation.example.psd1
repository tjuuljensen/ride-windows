# Disposable-VM controller seed example. SchemaVersion 2; replace placeholder IDs/paths in a local configuration before registration. No runtime credentials are stored here.
# Owner: RIDE-Windows maintainers. Keep values as declarative data.
# Versioning: SchemaVersion governs the data contract; no independent script CLI/version.

@{
  SchemaVersion = 2
  # Optional nonsecret reference to a dedicated VmTest enrollment under the host account.
  # GuestGitHubCredentialReference = 'vm-public-releases'
  Name = 'RIDEWin11Pilot'
  IsDisposable = $true
  LabName = 'RIDEWin11Pilot'
  VMName = 'RIDE-W11-Pilot'
  VMId = '00000000-0000-0000-0000-000000000000' # Replace with (Get-VM -Name ...).Id
  CheckpointName = 'RIDE-clean-test-base'
  GuestRepositoryPath = 'C:\RIDE\ride-windows'
  LocalRepositoryPath = 'C:\Users\YOUR-ACCOUNT\git\ride-windows'
  CIRepositoryPath = 'C:\RIDE-CI\runner\_work\ride-windows\ride-windows'
  IsoPath = 'D:\LabSources\ISOs\YOUR-WINDOWS-ISO.iso'
}
