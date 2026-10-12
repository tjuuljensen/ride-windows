# Minimal starter selection. -Add appends author-selected entries here; review it.
@{
  SchemaVersion = 1
  Name = 'Example library starter'
  Description = 'Select only the inert registry marker; no context menu or packages.'
  Operations = @(
    @{ Id = 'example.library.preference-marker'; State = 'Enabled' }
  )
}
