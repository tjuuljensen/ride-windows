@{
  SchemaVersion = 1
  Name = 'Analyst basics'
  Description = 'Install the small utility bundle used by analyst workstations.'
  Operations = @(
    @{ Id = 'solution.analyst-basics'; State = 'Present' }
  )
}
