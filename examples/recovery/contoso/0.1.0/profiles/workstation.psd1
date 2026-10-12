# Example selection only; review before applying. Owner: RIDE-Windows maintainers.
@{
  SchemaVersion = 1
  Name = 'Example organization workstation'
  Description = 'Select the inert external marker and reuse the built-in 7-Zip operation.'
  Operations = @(
    @{ Id = 'example.contoso.preference-marker'; State = 'Enabled' }
    @{ Id = 'example.contoso.utilities'; State = 'Present' }
  )
}
