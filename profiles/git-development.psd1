# Optional Git and standalone Git LFS solution; apply/remove in catalog dependency order.
# Owner: RIDE-Windows maintainers. SchemaVersion governs the data contract.
@{
  SchemaVersion = 1
  Name = 'Git development'
  Description = 'Machine Git for Windows and standalone Git LFS; separate from the bundled Git component.'
  Operations = @(@{ Id = 'solution.git-development'; State = 'Present' })
}
