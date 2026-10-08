# Documented RIDE baseline selection for the Explorer extension setting. SchemaVersion 1; this is not exact saved-state restoration or a whole-system Windows default.
# Owner: RIDE-Windows maintainers. Keep values as declarative data.
# Versioning: SchemaVersion governs the data contract; no independent script CLI/version.

@{
  SchemaVersion = 1
  Name = 'RIDE documented baseline'
  Description = 'Apply each operation baseline state declared in the catalog.'
  Operations = @(
    @{ Id = 'windows.show-known-extensions'; State = 'Baseline' }
  )
}
