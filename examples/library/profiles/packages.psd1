# Optional package selection; requires elevation and disposable-VM acceptance.
@{
  SchemaVersion = 1
  Name = 'Example library packages'
  Description = 'Select the built-in 7-Zip reference and the unverified Windows 7 Games example; no settings.'
  Operations = @(
    @{ Id = 'example.library.utilities'; State = 'Present' }
    @{ Id = 'example.library.classic-msgames'; State = 'Present' }
  )
}
