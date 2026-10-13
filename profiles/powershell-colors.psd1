# Optional PowerShell startup configuration; both runtimes must be installed.
# Owner: RIDE-Windows maintainers. Target/visual VM acceptance remains pending.
@{
  SchemaVersion = 1
  Name = 'PowerShell session colors'
  Description = 'Distinct normal-session colors for 5.1 and 7; consistent administrator blue. See docs/powershell-profiles.md before applying.'
  Operations = @(
    @{ Id = 'powershell.windows-powershell51-terminal-colors'; State = 'Recommended' }
    @{ Id = 'powershell.powershell7-terminal-colors'; State = 'Recommended' }
  )
}
