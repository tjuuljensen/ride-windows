# Main copyable library example. Owner: RIDE-Windows maintainers.
@{
  SchemaVersion = 1
  Id = 'example.library'
  Version = '0.1.1'
  EngineApiVersion = 1
  Catalog = 'catalog/operations.psd1'
  Profiles = @('profiles/custom.psd1', 'profiles/settings.psd1', 'profiles/packages.psd1')
}
