@{
  SchemaVersion = 1
  Name = 'RIDE documented baseline'
  Description = 'Apply each operation baseline state declared in the catalog.'
  Operations = @(
    @{ Id = 'windows.show-known-extensions'; State = 'Baseline' }
  )
}
