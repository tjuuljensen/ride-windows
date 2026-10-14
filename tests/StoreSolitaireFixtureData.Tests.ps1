BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Root 'tests/integration/RIDE.StoreSolitaireFixtureData.psm1') -Force
  $script:Text=[IO.File]::ReadAllText((Join-Path $script:Root 'catalog/operations.psd1'))
}
Describe 'Isolated Solitaire fixture data' {
  It 'changes exactly one Solitaire target array and preserves the rest of the catalog' {
    $changed=Get-RideSolitaireFixtureCatalog $script:Text
    $changed.Length|Should -Be ($script:Text.Length+12)
    $changed.Replace("@('Windows 11')",'@()')|Should -Not -Be $script:Text
    $errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($changed,[ref]$null,[ref]$errors)
    $errors.Count|Should -Be 0
    $original=[Management.Automation.Language.Parser]::ParseInput($script:Text,[ref]$null,[ref]$null)
    $before=@($original.FindAll({param($n) $n -is [Management.Automation.Language.HashtableAst] -and $n.Extent.Text -match "Id = 'app.solitaire'"},$true))[-1]
    $after=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.HashtableAst] -and $n.Extent.Text -match "Id = 'app.solitaire'"},$true))[-1]
    $changed.Substring(0,$after.Extent.StartOffset)|Should -BeExactly $script:Text.Substring(0,$before.Extent.StartOffset)
    $changed.Substring($after.Extent.EndOffset)|Should -BeExactly $script:Text.Substring($before.Extent.EndOffset)
    $after.SafeGetValue().SupportedTargets|Should -Be @('Windows 11')
  }
  It 'refuses already widened Solitaire support' { {Get-RideSolitaireFixtureCatalog (Get-RideSolitaireFixtureCatalog $script:Text)}|Should -Throw '*contract changed*' }
  It 'refuses missing or duplicated exact identity' {
    {Get-RideSolitaireFixtureCatalog $script:Text.Replace("Id = 'app.solitaire'","Id = 'app.other'")}|Should -Throw '*Exactly one*'
    {Get-RideSolitaireFixtureCatalog ($script:Text+"`n@{Id='app.solitaire'}")}|Should -Throw '*Exactly one*'
  }
  It 'refuses weakened protection metadata' { {Get-RideSolitaireFixtureCatalog $script:Text.Replace('RequireKnownProtectionFlags = $true','RequireKnownProtectionFlags = $false')}|Should -Throw '*contract changed*' }
  It 'accepts only the exact request and rejects additional actions and other apps' {
    $path=Join-Path $TestDrive 'request.json';$id='a'*32
    $r=[ordered]@{SchemaVersion=1;Scenario='StoreSolitaireLifecycle';RunId=$id;ExpectedUserSid='S-1-5-21-1-2-3-1000';ExpectedUserName='GUEST\admin';OperationId='app.solitaire';OriginalCatalogSHA256=('A'*64);CandidateCatalogSHA256=('B'*64)}
    $r|ConvertTo-Json|Set-Content $path
    (Read-RideSolitaireFixtureRequest $path $id).OperationId|Should -BeExactly 'app.solitaire'
    {Read-RideSolitaireFixtureRequest $path ('b'*32)}|Should -Throw '*Invalid*'
    $r.OperationId='app.news';$r|ConvertTo-Json|Set-Content $path
    {Read-RideSolitaireFixtureRequest $path $id}|Should -Throw '*Invalid*'
    $r.OperationId='app.solitaire';$r.Action='Uninstall';$r|ConvertTo-Json|Set-Content $path
    {Read-RideSolitaireFixtureRequest $path $id}|Should -Throw '*Invalid*'
  }
}
