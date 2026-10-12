<#
.SYNOPSIS
  Verify literal catalog search and runner completion without Windows changes.
.DESCRIPTION
  Uses declarative fixture catalogs and an isolated runner copy with no engine or
  handlers. Checks matching, evidence, view consistency, errors and completion.
.EXAMPLE
  Invoke-Pester .\tests\Search.Tests.ps1
.INPUTS
  None. Invoked through Pester.
.OUTPUTS
  Pester test results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; Pester 5.x.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
  Scratch data uses TestDrive; no Windows state is inspected or changed.
  Unloads copied runner modules after the container to isolate later tests.
#>

BeforeAll {
  $script:Root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Root 'modules/RIDE.Discovery.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.CatalogData.psm1') -Force
  $script:Fixture = Join-Path $TestDrive 'catalog.psd1'
  @'
@{
  SchemaVersion = 1
  Operations = @(
    @{
      Id = 'windows.desktop-folder-alpha'; Name = 'File Explorer [literal]*? (test)'
      Kind = 'RegistryValueSet'; Category = 'Windows settings / Explorer'
      Description = 'Desktop folder controls'; Scope = 'Machine'; RequiresAdmin = $true
      Actions = @('Get', 'Test', 'Set', 'Restore'); SupportedTargets = @('Fixture target')
      States = @{ Hidden = @{ Native = 'Hide' }; Visible = @{ Native = 'Show' } }
      RegistryValues = @(
        @{ RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\'; ValueName = 'ThisPCPolicy' }
        @{ RegistryPath = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\'; ValueName = 'ThisPCPolicy' }
      )
    }
    @{
      Id = 'windows.desktop-folder-beta'; Name = 'Desktop folder'; Kind = 'RegistryKeySet'
      Category = 'Windows settings / Explorer'; Description = 'File Explorer controls'
      RegistryPaths = @('HKLM:\Software\First', 'HKLM:\Software\Second')
      ValueNames = @('FirstValue', 'SecondValue')
    }
    @{
      Id = 'windows.service'; Name = 'Network service'; Kind = 'WindowsService'
      Category = 'Windows settings / Network'; Description = 'Inspect a service'
      ServiceName = 'FixtureService'; RegistryPath = 'HKLM:\Software\Service'; ValueName = 'Start'
    }
    @{
      Id = 'package.literal'; Name = 'Literal application'; Kind = 'Package'
      Category = 'Software / Utilities'; Description = 'Install a package'; PackageId = 'Literal.App'
      ProductUri = 'https://example.invalid/only-url-marker'
      InstallerArguments = 'only-installer-marker'; LegacySelectors = @('only-legacy-marker')
      TargetDefaults = @{ test = @{ EffectiveDefault = 'only-default-marker' } }
    }
    @{
      Id = 'artifact.literal'; Name = 'Literal artifact'; Kind = 'Artifact'
      Category = 'Software / Utilities'; Description = 'Download an artifact'; ArtifactId = 'FixtureArtifact'
    }
    @{
      Id = 'windows.power'; Name = 'Power control'; Kind = 'PowerSetting'
      Category = 'Windows settings / Power'; Description = 'Set a power value'
      PowerSettingGuid = 'abc-123'; PowerSubgroupGuid = 'def-456'
    }
  )
  Groups = @(
    @{ Id = 'group.literal'; Name = 'Literal solution'; Category = 'Software / Utilities'
      Description = 'A package group'; Members = @('package.literal'); Actions = @('Install', 'Remove') }
  )
}
'@ | Set-Content -LiteralPath $script:Fixture -Encoding UTF8
  $script:FixtureCatalog = Import-RideCatalogData -Path $script:Fixture
  $script:IsolatedRoot = Join-Path $TestDrive 'isolated runner'
  New-Item -ItemType Directory -Path (Join-Path $script:IsolatedRoot 'modules'), (Join-Path $script:IsolatedRoot 'catalog') | Out-Null
  Copy-Item -LiteralPath (Join-Path $script:Root 'ride.ps1') -Destination $script:IsolatedRoot
  foreach ($module in @('RIDE.Discovery.psm1', 'RIDE.CatalogData.psm1', 'RIDE.LibrarySchema.psm1', 'RIDE.Libraries.psm1', 'RIDE.SettingPresentation.psm1')) {
    Copy-Item -LiteralPath (Join-Path $script:Root "modules/$module") -Destination (Join-Path $script:IsolatedRoot 'modules')
  }
  Copy-Item -LiteralPath $script:Fixture -Destination (Join-Path $script:IsolatedRoot 'catalog/operations.psd1')
  $script:Runner = Join-Path $script:IsolatedRoot 'ride.ps1'
}

AfterAll {
  # Copied discovery dependencies remain loaded after an in-process runner call.
  # Remove only this fixture's copies so later Pester mocks resolve one module.
  $modulePrefix = $script:IsolatedRoot + [IO.Path]::DirectorySeparatorChar
  Get-Module -All | Where-Object {
    $_.Path -and $_.Path.StartsWith($modulePrefix, [StringComparison]::OrdinalIgnoreCase)
  } | Remove-Module -Force
}

Describe 'Literal catalog search' {
  It 'finds IDs irrespective of case and returns one object per entry' {
    $rows = @(Find-RideCatalog DESKTOP-FOLDER -CatalogPath $script:Fixture)
    $rows.Count | Should -Be 2
    $rows[0].Id | Should -Be 'windows.desktop-folder-beta'
    $rows[1].Id | Should -Be 'windows.desktop-folder-alpha'
    $rows[0].MatchedFields | Should -Be @('Id')
    $rows[0] | Should -BeOfType ([pscustomobject])
  }

  It 'keeps a phrase together and does not join separate field values' {
    @(Find-RideCatalog 'File Explorer' -CatalogPath $script:Fixture).Count | Should -Be 2
    @(Find-RideCatalog 'Explorer Desktop' -CatalogPath $script:Fixture).Count | Should -Be 0
    @(Find-RideCatalog 'First HKLM' -Field RegistryPath -CatalogPath $script:Fixture).Count | Should -Be 0
  }

  It 'matches independently of the current user culture' {
    $originalCulture = [Threading.Thread]::CurrentThread.CurrentCulture
    try {
      [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('tr-TR')
      @(Find-RideCatalog 'FILE EXPLORER' -CatalogPath $script:Fixture).Count | Should -Be 2
    }
    finally { [Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture }
  }

  It 'matches punctuation literally: <Query>' -ForEach @(
    @{ Query = '[literal]*?' }, @{ Query = '(test)' }, @{ Query = '*' }, @{ Query = '?' }
  ) {
    $rows = @(Find-RideCatalog $Query -CatalogPath $script:Fixture)
    $rows.Count | Should -Be 1
    $rows[0].Id | Should -Be 'windows.desktop-folder-alpha'
  }

  It 'searches nested paths and retains their full source evidence' {
    $query = 'Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\'
    $row = Find-RideCatalog $query -Field RegistryPath -CatalogPath $script:Fixture
    $row.Id | Should -Be 'windows.desktop-folder-alpha'
    $row.Matches.Count | Should -Be 1
    $row.Matches[0].Source | Should -Be 'RegistryValues[1].RegistryPath'
    $row.Matches[0].Value | Should -Be ('HKLM:\SOFTWARE\' + $query)
    $row.SupportedTargets | Should -Be @('Fixture target')
    @(Find-RideCatalog ($query + '\') -Field RegistryPath -CatalogPath $script:Fixture).Count | Should -Be 0
  }

  It 'searches plural and singular registry metadata' {
    (Find-RideCatalog Second -Field RegistryPath -CatalogPath $script:Fixture).Matches[0].Source | Should -Be 'RegistryPaths[1]'
    (Find-RideCatalog SecondValue -Field ValueName -CatalogPath $script:Fixture).Matches[0].Source | Should -Be 'ValueNames[1]'
    (Find-RideCatalog '\Service' -Field RegistryPath -CatalogPath $script:Fixture).Id | Should -Be 'windows.service'
    (Find-RideCatalog Start -Field ValueName -CatalogPath $script:Fixture).Id | Should -Be 'windows.service'
  }

  It 'retains multiple matches in one result and deduplicates selected fields' {
    $rows = @(Find-RideCatalog ThisPCPolicy -Field valuename,ValueName -CatalogPath $script:Fixture)
    $rows.Count | Should -Be 1
    $rows[0].MatchedFields | Should -Be @('ValueName')
    $rows[0].Matches.Count | Should -Be 2
  }

  It 'narrows fields and applies OR semantics across selected fields' {
    (Find-RideCatalog 'File Explorer' -Field Name -CatalogPath $script:Fixture).Id | Should -Be 'windows.desktop-folder-alpha'
    (Find-RideCatalog 'File Explorer' -Field Description -CatalogPath $script:Fixture).Id | Should -Be 'windows.desktop-folder-beta'
    @(Find-RideCatalog 'File Explorer' -Field Name,Description -CatalogPath $script:Fixture).Count | Should -Be 2
  }

  It 'reports every matching field in contract order with a compact object display' {
    $row = Find-RideCatalog Desktop -Field Description,Id -CatalogPath $script:Fixture | Where-Object Id -eq 'windows.desktop-folder-alpha'
    $row.MatchedFields | Should -Be @('Id', 'Description')
    @($row.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames) | Should -Be @('Id', 'Name', 'Kind', 'Scope', 'RequiresAdmin', 'Behavior', 'MatchedFields')
  }

  It 'searches technical resource identifiers: <Query>' -ForEach @(
    @{ Query = 'Literal.App'; Id = 'package.literal' },
    @{ Query = 'FixtureService'; Id = 'windows.service' },
    @{ Query = 'FixtureArtifact'; Id = 'artifact.literal' },
    @{ Query = 'abc-123'; Id = 'windows.power' }
  ) {
    (Find-RideCatalog $Query -Field ResourceId -CatalogPath $script:Fixture).Id | Should -Be $Id
  }

  It 'keeps unrelated catalog fields outside the search contract: <Query>' -ForEach @(
    @{ Query = 'only-url-marker' }, @{ Query = 'only-installer-marker' },
    @{ Query = 'only-legacy-marker' }, @{ Query = 'only-default-marker' }
  ) {
    @(Find-RideCatalog $Query -CatalogPath $script:Fixture).Count | Should -Be 0
  }

  It 'filters packages artifacts groups and categories with shared view selection' {
    foreach ($view in @('all', 'packages', 'artifacts', 'groups', 'settings', 'explorer', 'windows', 'windows-settings', 'Windows settings', 'software', 'utilities')) {
      $expected = @(Select-RideCatalogView -Catalog $script:FixtureCatalog -Rows @(Get-RideCatalogRows $script:FixtureCatalog) -View $view |
        Where-Object { $_.Id.IndexOf('literal', [StringComparison]::OrdinalIgnoreCase) -ge 0 } | Sort-Object Type,Category,Name,Id)
      $actual = @(Find-RideCatalog literal -Field Id -View $view -CatalogPath $script:Fixture)
      ($actual.Id -join ',') | Should -Be ($expected.Id -join ',')
    }
    (Find-RideCatalog literal -View group -CatalogPath $script:Fixture).Members | Should -Be @('package.literal')
    @(Find-RideCatalog nonexistent -View packages -CatalogPath $script:Fixture).Count | Should -Be 0
  }

  It 'rejects unknown views and fields and empty selections' {
    { Find-RideCatalog x -View profiles -CatalogPath $script:Fixture } | Should -Throw '*Unknown catalog view*'
    { Find-RideCatalog x -View nowhere -CatalogPath $script:Fixture } | Should -Throw '*Unknown catalog view*'
    { Find-RideCatalog x -Field InstallerArguments -CatalogPath $script:Fixture } | Should -Throw '*Unknown search field*'
    { Find-RideCatalog x -Field @() -CatalogPath $script:Fixture } | Should -Throw '*at least one*'
    { Find-RideCatalog '   ' -CatalogPath $script:Fixture } | Should -Throw '*nonblank*'
  }

  It 'rejects a malformed catalog without executing it' {
    $badPath = Join-Path $TestDrive 'bad.psd1'
    '@{ SchemaVersion = 1; Operations = @(Get-Process); Groups = @() }' | Set-Content -LiteralPath $badPath
    { Find-RideCatalog x -CatalogPath $badPath } | Should -Throw
  }
}

Describe 'Search runner and completion' {
  It 'supports positional and named queries with no engine handlers profiles or state storage' {
    $before = @(Get-ChildItem -LiteralPath $script:IsolatedRoot -Recurse -File | ForEach-Object FullName)
    $positional = @(& $script:Runner desktop-folder -Command search)
    $named = @(& $script:Runner -Command search -Query desktop-folder)
    ($positional.Id -join ',') | Should -Be ($named.Id -join ',')
    $positional.Count | Should -Be 2
    @(& $script:Runner search nonexistent).Count | Should -Be 0
    (@(Get-ChildItem -LiteralPath $script:IsolatedRoot -Recurse -File | ForEach-Object FullName) -join ',') | Should -Be ($before -join ',')
    ($positional[0].PSObject.Properties.Name) | Should -Contain 'Matches'
    ($positional[0].PSObject.Properties.Name) | Should -Contain 'Description'
    @($positional[0].Members).Count | Should -Be 0
  }

  It 'rejects missing blank ambiguous and action-related arguments' {
    { & $script:Runner search } | Should -Throw '*nonblank query*'
    { & $script:Runner search ' ' } | Should -Throw '*nonblank query*'
    { & $script:Runner search x -Query y } | Should -Throw '*not both*'
    foreach ($parameter in @('Profile', 'State', 'RunId', 'Destination', 'WhatIf', 'Confirm')) {
      $arguments = @{}; $arguments[$parameter] = if ($parameter -in @('WhatIf', 'Confirm')) { $false } else { 'x' }
      { & $script:Runner search x @arguments } | Should -Throw '*does not accept*'
    }
    { & $script:Runner list -Query x } | Should -Throw '*only supported*'
    { & $script:Runner list -Field Name } | Should -Throw '*only supported*'
    { & $script:Runner list -View packages } | Should -Throw '*only supported*'
    { & $script:Runner search x -Regex } | Should -Throw
  }

  It 'completes commands query IDs fields and catalog-derived views: <Suffix>' -ForEach @(
    @{ Suffix = 'se'; Expected = 'search' },
    @{ Suffix = 'search WINDOWS.DESKTOP-'; Expected = 'windows.desktop-folder-alpha' },
    @{ Suffix = '-Command search -Query windows.desktop-'; Expected = 'windows.desktop-folder-alpha' },
    @{ Suffix = 'search x -Field reg'; Expected = 'RegistryPath' },
    @{ Suffix = 'search x -Field Name,Des'; Expected = 'Description' },
    @{ Suffix = 'search x -View exp'; Expected = 'explorer' },
    @{ Suffix = 'search x -View net'; Expected = 'network' },
    @{ Suffix = 'list art'; Expected = 'artifacts' }
  ) {
    $line = "& '$script:Runner' $Suffix"
    $matches = @((TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText)
    $matches | Should -Contain $Expected
    @($matches | Sort-Object -Unique).Count | Should -Be $matches.Count
    if ($Suffix -like '*-View*') { $matches | Should -Not -Contain 'profiles' }
  }

  It 'fails quietly when completion catalog data is unavailable' {
    $missingRoot = Join-Path $TestDrive 'missing catalog'
    New-Item -ItemType Directory -Path $missingRoot | Out-Null
    Copy-Item -LiteralPath $script:Runner -Destination $missingRoot
    $line = "& '$(Join-Path $missingRoot 'ride.ps1')' search x -View exp"
    { TabExpansion2 -InputScript $line -CursorColumn $line.Length -ErrorAction Stop | Out-Null } | Should -Not -Throw
  }

  It 'does not suggest setting states after a search query' {
    $line = "& '$script:Runner' search windows.desktop-folder-alpha "
    $matches = @((TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText)
    $matches | Should -Not -Contain 'Hidden'
    $matches | Should -Not -Contain 'Visible'
    $line = "& '$script:Runner' set windows.desktop-folder-alpha "
    (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText | Should -Contain 'Hidden'
  }

  It 'completes module field and view parameters using the selected catalog' {
    $line = 'Find-RideCatalog x -Field val'
    (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText | Should -Contain 'ValueName'
    $line = "Find-RideCatalog x -CatalogPath '$script:Fixture' -View net"
    (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText | Should -Contain 'network'
  }

  It 'shares list projection and views without changing existing profile discovery' {
    Import-Module (Join-Path $script:Root 'modules/RIDE.Engine.psm1') -Force
    $listed = @(& (Join-Path $script:Root 'ride.ps1') list explorer)
    $searched = @(& (Join-Path $script:Root 'ride.ps1') search Explorer -Field Category -View explorer)
    ($listed.Id -join ',') | Should -Be ($searched.Id -join ',')
    foreach ($property in @('Type', 'Id', 'Name', 'Category', 'Kind', 'Scope', 'RequiresAdmin', 'Actions', 'Members', 'Path', 'Description', 'SupportedTargets', 'ProductUri', 'License', 'LicenseUri', 'TermsUri')) {
      $searched[0].PSObject.Properties.Name | Should -Contain $property
      $listed[0].PSObject.Properties.Name | Should -Contain $property
    }
    @(& (Join-Path $script:Root 'ride.ps1') list profiles).Count | Should -BeGreaterThan 0
  }

  It 'reports search in both help surfaces' {
    (& $script:Runner -Help) | Should -Match 'search <query>'
    (Get-Help -Name $script:Runner -Full | Out-String) | Should -Match 'Query'
  }
}
