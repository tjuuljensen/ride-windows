# Optional PowerShell startup configuration; both runtimes must be installed.
# Accepted on Windows 11 and Server 2025 Desktop Experience with Windows Terminal.
@{
  SchemaVersion = 1
  Name = 'PowerShell session colors'
  Description = 'Distinct normal-session colors for 5.1 and 7; consistent administrator blue. See docs/powershell-profiles.md before applying.'
  Operations = @(
    @{ Id = 'powershell.windows-powershell51-terminal-colors'; State = 'Recommended' }
    @{ Id = 'powershell.powershell7-terminal-colors'; State = 'Recommended' }
  )
}
