# Request-bound Windows 11 hibernation configuration acceptance template.
# Replace RunId in a disposable source copy and name it
# tests/integration/settings-validation.fixture.psd1. Never enable public targets.
@{
  SchemaVersion = 2
  RunId = '00000000000000000000000000000000'
  IntegrationSuite = 'SettingsBatch60'
  Target = 'Windows 11'
  Scenario = 'HibernationMatrix'
  OperationId = 'windows.hibernation'
  States = @('Off', 'Full', 'Reduced', 'Size50', 'Size75', 'Size100')
  AllowPendingCandidate = $true
}
