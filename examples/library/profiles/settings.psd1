# Optional settings selection; review and test in a disposable Windows VM.
@{
  SchemaVersion = 1
  Name = 'Example library settings'
  Description = 'Select the inert marker and optional SHA-256 Certutil context menu; no packages.'
  Operations = @(
    @{ Id = 'example.library.preference-marker'; State = 'Enabled' }
    @{ Id = 'example.library.sha256-certutil'; State = 'Enabled' }
  )
}
