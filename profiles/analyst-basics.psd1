# Analyst utility solution selection. SchemaVersion 1; declarative data consumed by the RIDE engine, not an executable script.
# Owner: RIDE-Windows maintainers. Keep values as declarative data.
# Versioning: SchemaVersion governs the data contract; no independent script CLI/version.

@{
  SchemaVersion = 1
  Name = 'Analyst basics'
  Description = 'Install the small utility bundle used by analyst workstations.'
  Operations = @(
    @{ Id = 'solution.analyst-basics'; State = 'Present' }
  )
}
