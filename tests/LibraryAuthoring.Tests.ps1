<#
.SYNOPSIS
  Verify guided custom-library authoring without installers or network access.
.DESCRIPTION
  Uses temporary projects, scripted console input and mocked package processes.
.EXAMPLE
  Invoke-Pester .\tests\LibraryAuthoring.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
#>

BeforeAll {
  $script:Root = Split-Path -Parent $PSScriptRoot
  $script:Helper = Join-Path $script:Root 'tools/New-RideLibrary.ps1'
  Import-Module (Join-Path $script:Root 'modules/RIDE.LibraryAuthoring.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.LibrarySchema.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.Libraries.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.CatalogValidation.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE-Packages.psm1') -Force
  function New-AuthoringFixture {
    @{
      Id = 'test.author'; Version = '0.1.0'; Operations = @(
        @{
          Id = 'app'; Kind = 'Package'; Name = "Author's App"; Description = 'Test-only metadata; never installed.'
          Scope = 'Machine'; SupportedTargets = @('Windows 11'); InstallerType = 'Exe'; Architecture = 'x64'
          DownloadProvider = 'DirectHttps'; DownloadUri = 'https://publisher.example.invalid/app-1.exe'
          PackageVersion = '1.2.3'; AssetName = 'app.exe'; DisplayNamePattern = '^Example App$'
          InstallerArguments = '/S'; UninstallerArguments = '/S'; License = 'MIT'; LicenseUri = 'https://publisher.example.invalid/license'
        }
      )
    }
  }
  function Get-GeneratedOperation([string] $Manifest) {
    (Get-RideCatalogContext -Root $script:Root -Library $Manifest).Catalog.Operations | Where-Object Id -eq 'test.author.app'
  }
}

Describe 'Custom-library authoring' {
  BeforeEach {
    $script:ProjectPath = Join-Path $TestDrive ('project-' + [guid]::NewGuid().ToString('N'))
    $script:DefinitionData = New-AuthoringFixture
  }

  It 'publishes an external package with optional references omitted and a loadable profile' {
    $project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false
    $operation = Get-GeneratedOperation $project.Manifest
    $operation.Name | Should -Be "Author's App"
    $operation.ContainsKey('ProductUri') | Should -BeFalse
    $operation.ContainsKey('RecoveryUri') | Should -BeFalse
    $operation.PackageId | Should -Be 'test.author.app'
    $operation.Rollback | Should -Be 'Compensating'
    $operation.RequiresAdmin | Should -BeTrue
    (Import-PowerShellDataFile -LiteralPath $project.Profile).Operations[0].State | Should -Be 'Present'
  }

  It 'generates an MSI package using the same lifecycle and source contract' {
    $inputOperation = $script:DefinitionData.Operations[0]
    $inputOperation.InstallerType = 'Msi'; $inputOperation.AssetName = 'app.msi'
    $inputOperation.InstallerArguments = '/qn /norestart'; $inputOperation.UninstallerArguments = '/qn /norestart'
    $project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false
    (Get-GeneratedOperation $project.Manifest).InstallerType | Should -Be 'Msi'
  }

  It 'offers supported types from the metadata contract and the same target catalog' {
    $choices = Get-RideLibraryAuthoringOptions
    $choices.Kinds | Should -Be @('Package', 'RegistryValue', 'RegistryValueSet')
    $choices.InstallerTypes | Should -Be @('Exe', 'Msi')
    $choices.DownloadProviders | Should -Contain 'DirectHttps'
    $engineCount = @(Get-Module RIDE.Engine).Count
    $rows = @(& $script:Helper -ShowOptions)
    ($rows | Where-Object Field -eq Kinds).Choices | Should -Be $choices.Kinds
    @(Get-Module RIDE.Engine).Count | Should -Be $engineCount
  }

  It 'rejects unsupported operation kinds, formats and mismatched extensions' {
    $script:DefinitionData.Operations[0].Kind = 'WindowsService'
    { New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false } | Should -Throw '*supported operation kind*'
    $script:DefinitionData.Operations[0].Kind = 'Package'; $script:DefinitionData.Operations[0].InstallerType = 'Zip'
    { New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false } | Should -Throw '*supported installer*'
    $script:DefinitionData.Operations[0].InstallerType = 'Msi'
    { New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false } | Should -Throw '*matching EXE/MSI*'
    Test-Path -LiteralPath $script:ProjectPath | Should -BeFalse
    @(Get-ChildItem -LiteralPath $TestDrive -Directory -Filter '.ride-library-*').Count | Should -Be 0
  }

  It 'keeps a download source and license summary mandatory while allowing no license URL' {
    $script:DefinitionData.Operations[0].Remove('DownloadUri')
    { New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false } | Should -Throw '*DownloadUri*'
    $script:DefinitionData = New-AuthoringFixture
    $script:DefinitionData.Operations[0].Remove('LicenseUri')
    $project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false
    (Get-GeneratedOperation $project.Manifest).ContainsKey('LicenseUri') | Should -BeFalse
    $script:DefinitionData.Operations[0].Remove('License')
    { New-RideLibraryProject -Path ($script:ProjectPath + '-missing-license') -Definition $script:DefinitionData -Confirm:$false } | Should -Throw '*license summary*'
  }

  It 'accepts custom license and terms links at <Uri>' -TestCases @(
    @{ Uri = 'http://internal-server/licenses/app' }, @{ Uri = 'http://localhost:8080/license.txt' }, @{ Uri = 'https://publisher.example.invalid/license' }
  ) {
    param($Uri)
    $script:DefinitionData.Operations[0].LicenseUri = $Uri
    $script:DefinitionData.Operations[0].TermsUri = $Uri
    $project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false
    (Get-GeneratedOperation $project.Manifest).LicenseUri | Should -Be $Uri
  }

  It 'exports a missing license URL as text without an empty Markdown link' {
    $script:DefinitionData.Operations[0].Remove('LicenseUri')
    $project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false
    $reference = Join-Path $TestDrive 'custom-reference.md'
    & (Join-Path $script:Root 'tools/Export-RideCatalog.ps1') -Library $project.Manifest -OutputPath $reference | Out-Null
    $content = [IO.File]::ReadAllText($reference)
    $content | Should -Match '\| test\.author\.app \| MIT \| Not provided \|'
    $content | Should -Not -Match '\[License\]\(\)'
  }

  It 'rejects malformed or active-content license links when supplied' -TestCases @(
    @{ Uri = 'javascript:alert(1)' }, @{ Uri = 'license.txt' }, @{ Uri = '' }, @{ Uri = 'http://user:password@localhost/license' }
  ) {
    param($Uri)
    $script:DefinitionData.Operations[0].LicenseUri = $Uri
    { New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false } | Should -Throw '*Custom LicenseUri*HTTP/HTTPS*'
  }

  It 'validates optional product and recovery URLs when supplied' {
    $script:DefinitionData.Operations[0].ProductUri = 'http://publisher.example.invalid/app'
    { New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false } | Should -Throw '*HTTPS product URI*'
    $script:DefinitionData.Operations[0].ProductUri = 'https://publisher.example.invalid/app'
    $script:DefinitionData.Operations[0].RecoveryUri = 'javascript:evil'
    { New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false } | Should -Throw '*Recovery information*'
    $script:DefinitionData.Operations[0].RecoveryUri = 'https://publisher.example.invalid/recovery'
    $project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false
    (Get-GeneratedOperation $project.Manifest).RecoveryUri | Should -Be 'https://publisher.example.invalid/recovery'
  }

  It 'retains mandatory documentation and product references for built-in entries' {
    $builtin = Import-RideCatalogData -Path (Join-Path $script:Root 'catalog/operations.psd1')
    ($builtin.Operations | Where-Object Kind -eq RegistryValue | Select-Object -First 1).Remove('DocumentationUri')
    ($builtin.Operations | Where-Object Kind -eq Package | Select-Object -First 1).Remove('ProductUri')
    ($builtin.Operations | Where-Object Kind -eq Package | Select-Object -First 1).Remove('LicenseUri')
    $errors = @(Get-RideCatalogValidationErrors -Catalog $builtin)
    ($errors -join '|') | Should -Match 'missing Microsoft documentation URI'
    ($errors -join '|') | Should -Match 'missing product information URI'
    ($errors -join '|') | Should -Match 'HTTPS license URI'
  }

  It 'previews without files and refuses to replace an existing project' {
    New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -WhatIf | Out-Null
    Test-Path -LiteralPath $script:ProjectPath | Should -BeFalse
    $null = New-Item -ItemType Directory -Path $script:ProjectPath
    $sentinel = Join-Path $script:ProjectPath 'keep.txt'; Set-Content -LiteralPath $sentinel -Value 'keep'
    { New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false } | Should -Throw '*already exists*'
    Get-Content -LiteralPath $sentinel | Should -Be 'keep'
  }

  It 'round-trips literal PowerShell punctuation without executing author input' {
    $script:DefinitionData.Operations[0].Description = "Literal `$(Get-Process); 'quoted' | & text"
    $project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:DefinitionData -Confirm:$false
    (Get-GeneratedOperation $project.Manifest).Description | Should -Be $script:DefinitionData.Operations[0].Description
  }

  It 'rejects executable definition files and exposes native help and version without prompting' {
    $file = Join-Path $TestDrive 'bad.psd1'
    Set-Content -LiteralPath $file -Value 'Get-Process; @{ Id = "test.author" }'
    { & $script:Helper -Path $script:ProjectPath -Definition $file } | Should -Throw '*single declarative hashtable*'
    (& $script:Helper -Version) | Should -Be '0.5.0'
    (Get-Help $script:Helper -Full).Synopsis | Should -Match 'Guide an author'
    Test-Path -LiteralPath $script:ProjectPath | Should -BeFalse
  }

  Context 'Guided console prompts' {
    BeforeEach {
      $global:RideAuthoringTestPromptState = @{ Index = 0; Responses = @(); Prompts = @() }
      Mock Read-Host {
        param($Prompt)
        $state = $global:RideAuthoringTestPromptState
        $state.Prompts += $Prompt
        if ($state.Index -ge $state.Responses.Count) { throw 'Unexpected authoring prompt.' }
        $answer = $state.Responses[$state.Index]; $state.Index++; $answer
      }
    }
    AfterEach { Remove-Variable -Name RideAuthoringTestPromptState -Scope Global -ErrorAction SilentlyContinue }
    It 'guides a new package author through valid choices, retries an invalid choice and skips optional URLs' {
      $global:RideAuthoringTestPromptState.Responses = @('test.author', '', 'invalid', '1', '1', 'app', 'Example App', 'Test-only package', '2', '1', '1', '1', '1', '1',
        'https://publisher.example.invalid/app.exe', '1.2.3', 'app.exe', '', 'Example App', '/S', '/S', 'MIT',
        'https://publisher.example.invalid/license', '', '', '1', '', '1')
      $project = & $script:Helper -Path $script:ProjectPath -Confirm:$false
      $operation = Get-GeneratedOperation $project.Manifest
      $operation.DisplayNamePattern | Should -Be '^Example\ App$'
      @($global:RideAuthoringTestPromptState.Prompts | Where-Object { $_ -like '*Installed product name*not an included app*' }).Count | Should -Be 1
      $operation.InstallerType | Should -Be 'Exe'
      $operation.ContainsKey('ProductUri') | Should -BeFalse
      $global:RideAuthoringTestPromptState.Index | Should -Be $global:RideAuthoringTestPromptState.Responses.Count
    }
    It 'saves unknown package detection as a draft and resumes after registration is known' {
      $global:RideAuthoringTestPromptState.Responses = @('test.author', '', '1', '1', 'app', 'Example App', 'Test-only package', '2', '1', '1', '1', '1', '1',
        'https://publisher.example.invalid/app.exe', '1.2.3', 'app.exe', '', '', '/S', '/S', 'Unknown', '', '', '', '1', '', '1')
      & $script:Helper -Path $script:ProjectPath -Confirm:$false
      $draft = $script:ProjectPath + '.draft.psd1'
      Test-Path -LiteralPath $script:ProjectPath | Should -BeFalse
      Test-Path -LiteralPath $draft | Should -BeTrue
      (Import-PowerShellDataFile -LiteralPath $draft).Operations[0].DetectionDisplayName | Should -BeExactly ''
      { & $script:Helper -Path $script:ProjectPath -Definition $draft -Confirm:$false } | Should -Throw '*unknown installed-product name*'
      $global:RideAuthoringTestPromptState = @{ Index = 0; Responses = @('Registered Bundle'); Prompts = @() }
      $project = & $script:Helper -Path $script:ProjectPath -Definition $draft -ResumeDraft -Confirm:$false
      (Get-GeneratedOperation $project.Manifest).DisplayNamePattern | Should -Be '^Registered\ Bundle$'
      $global:RideAuthoringTestPromptState.Index | Should -Be 1
      Test-Path -LiteralPath $draft | Should -BeTrue
    }
    It 'creates a registry entry with a typed hexadecimal value and no documentation URL' {
      $global:RideAuthoringTestPromptState.Responses = @('test.author', '', '2', 'app', 'Example marker', 'Test-only registry value', '1', '1',
        'HKCU:\Software\RIDE\AuthoringTests', 'Marker', '4', '', '0xffffffff', '1', 'No marker in the standard image', '', '', '1')
      $project = & $script:Helper -Path $script:ProjectPath -Confirm:$false
      $operation = Get-GeneratedOperation $project.Manifest
      $operation.Kind | Should -Be 'RegistryValue'
      $operation.States.Enabled | Should -Be -1
      $operation.States.WindowsDefault | Should -BeNullOrEmpty
      $operation.ContainsKey('DocumentationUri') | Should -BeFalse
      $operation.RequiresAdmin | Should -BeFalse
      $global:RideAuthoringTestPromptState.Index | Should -Be $global:RideAuthoringTestPromptState.Responses.Count
    }
    It 'cancels without publishing a directory' {
      $global:RideAuthoringTestPromptState.Responses = @(':cancel')
      { & $script:Helper -Path $script:ProjectPath } | Should -Throw '*cancelled*'
      Test-Path -LiteralPath $script:ProjectPath | Should -BeFalse
    }
  }
}

Describe 'Direct HTTPS custom installers' {
  BeforeEach { $script:Package = (New-AuthoringFixture).Operations[0]; $script:Package.PackageId = 'test.author.app' }
  It 'resolves a pinned installer and optional digest without a network request' {
    Mock Invoke-RestMethod -ModuleName RIDE-Packages { throw 'No network calls are expected.' }
    Mock Invoke-WebRequest -ModuleName RIDE-Packages { throw 'No network calls are expected.' }
    $script:Package.ExpectedSha256 = 'a' * 64
    $artifact = Resolve-RidePackageArtifact -Operation $script:Package
    $artifact.Version | Should -Be '1.2.3'
    $artifact.ProviderDigest | Should -Be ('sha256:' + ('a' * 64))
    $artifact.OriginUri | Should -Be 'https://publisher.example.invalid'
    Should -Invoke Invoke-RestMethod -ModuleName RIDE-Packages -Times 0 -Exactly
    Should -Invoke Invoke-WebRequest -ModuleName RIDE-Packages -Times 0 -Exactly
  }
  It 'rejects unsafe filenames, sources and expected digests before downloading' {
    $script:Package.AssetName = '../app.exe'
    { Resolve-RidePackageArtifact -Operation $script:Package } | Should -Throw '*safe version*'
    $script:Package.AssetName = 'app.exe'; $script:Package.DownloadUri = 'https://name:password@publisher.example.invalid/app.exe'
    { Resolve-RidePackageArtifact -Operation $script:Package } | Should -Throw '*without credentials*'
    $script:Package.DownloadUri = 'https://publisher.example.invalid/app.exe'; $script:Package.ExpectedSha256 = 'bad'
    { Resolve-RidePackageArtifact -Operation $script:Package } | Should -Throw '*64 hexadecimal*'
  }
  It 'checks a direct installer checksum before retaining evidence or invoking a process' {
    $script:Package.ExpectedSha256 = '0' * 64
    Mock Invoke-WebRequest -ModuleName RIDE-Packages { [IO.File]::WriteAllText($OutFile, 'test-only payload') }
    Mock Add-RideArtifactObservation -ModuleName RIDE-Packages { throw 'Digest mismatch must stop before recording success.' }
    { Save-RidePackageArtifact -Operation $script:Package -DestinationDirectory (Join-Path $TestDrive 'direct-source') } | Should -Throw '*digest mismatch*'
    Should -Invoke Add-RideArtifactObservation -ModuleName RIDE-Packages -Times 0 -Exactly
  }
  It 'dispatches retained EXE and MSI installers through mocked processes' {
    Mock Get-RideInstalledPackage -ModuleName RIDE-Packages { [pscustomobject]@{ Present = $true } }
    Mock Save-RidePackageArtifact -ModuleName RIDE-Packages { [pscustomobject]@{ Path = 'C:\fixture\installer.msi' } }
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages { [pscustomobject]@{ ExitCode = 0 } }
    foreach ($type in @('Exe', 'Msi')) {
      $script:Package.InstallerType = $type
      Install-RidePackage -Operation $script:Package -CacheDirectory $TestDrive
    }
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Times 1 -Exactly -ParameterFilter { $FilePath -like '*msiexec.exe' -and $ArgumentList -like '/i *' }
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Times 1 -Exactly -ParameterFilter { $FilePath -eq 'C:\fixture\installer.msi' }
  }
}

Describe 'Add operations to a generated library' {
  BeforeEach {
    $script:ProjectPath = Join-Path $TestDrive ('append-' + [guid]::NewGuid().ToString('N'))
    $script:InitialDefinition = New-AuthoringFixture
    $script:InitialDefinition.Operations[0].Remove('LicenseUri')
    $script:Project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:InitialDefinition -Confirm:$false
    $script:BeforeHash = (Get-FileHash -LiteralPath (Join-Path $script:ProjectPath 'catalog/operations.psd1')).Hash
    $script:NewDefinition = New-AuthoringFixture
    $script:NewDefinition.Version = '0.1.1'
    $script:NewDefinition.Operations[0].Id = 'second-app'
    $script:NewDefinition.Operations[0].LicenseUri = 'http://localhost:8080/license'
    $sentinel = Join-Path $script:ProjectPath 'operator-notes.txt'
    [IO.File]::WriteAllText($sentinel, 'Keep this unrelated file exactly.')
  }

  It 'adds a package, preserves current selections/files and retains loadable exact previous metadata' {
    $updated = Add-RideLibraryOperation -Path $script:ProjectPath -Definition $script:NewDefinition -Confirm:$false
    $catalog = Import-RideCatalogData -Path (Join-Path $updated.Path 'catalog/operations.psd1')
    $catalog.Operations.Id | Should -Be @('test.author.app', 'test.author.second-app')
    $profile = Import-PowerShellDataFile -LiteralPath $updated.Profile
    $profile.Operations.Id | Should -Be @('test.author.app', 'test.author.second-app')
    (Get-RideCatalogContext -Root $script:Root -Library $updated.Manifest).Libraries[0].Version | Should -Be '0.1.1'
    $old = Get-RideCatalogContext -Root $script:Root -Library $updated.PreviousManifest
    $old.Libraries[0].Version | Should -Be '0.1.0'
    $old.Libraries[0].CatalogSha256 | Should -Be $script:BeforeHash.ToLowerInvariant()
    Get-Content -LiteralPath (Join-Path $script:ProjectPath 'operator-notes.txt') | Should -Be 'Keep this unrelated file exactly.'
    Test-Path -LiteralPath (Join-Path $script:ProjectPath '.ride-authoring.lock') | Should -BeFalse
  }

  It 'preserves existing groups, alternate profiles and explicit selections' {
    $catalogPath = Join-Path $script:ProjectPath 'catalog/operations.psd1'
    $text = [IO.File]::ReadAllText($catalogPath)
    $text = $text.Replace("'Groups' = @(`n  )", "'Groups' = @(`n    @{ Id = 'test.author.apps'; Name = 'Apps'; Category = 'Software'; Description = 'Existing solution'; Members = @('test.author.app'); Actions = @('Install', 'Uninstall'); Rollback = 'Compensating' }`n  )")
    [IO.File]::WriteAllText($catalogPath, $text, [Text.UTF8Encoding]::new($false))
    $profilePath = Join-Path $script:ProjectPath 'profiles/custom.psd1'
    $text = [IO.File]::ReadAllText($profilePath).Replace("'Present'", "'Absent'")
    [IO.File]::WriteAllText($profilePath, $text, [Text.UTF8Encoding]::new($false))
    $alternate = Join-Path $script:ProjectPath 'profiles/alternate.psd1'
    Copy-Item -LiteralPath $profilePath -Destination $alternate
    $manifestText = [IO.File]::ReadAllText($script:Project.Manifest).Replace("'profiles/custom.psd1'", "'profiles/custom.psd1'`n    'profiles/alternate.psd1'")
    [IO.File]::WriteAllText($script:Project.Manifest, $manifestText, [Text.UTF8Encoding]::new($false))
    $alternateHash = (Get-FileHash -LiteralPath $alternate).Hash
    $updated = Add-RideLibraryOperation -Path $script:ProjectPath -Definition $script:NewDefinition -Confirm:$false
    (Import-RideCatalogData -Path $catalogPath).Groups[0].Id | Should -Be 'test.author.apps'
    (Import-PowerShellDataFile -LiteralPath $profilePath).Operations[0].State | Should -Be 'Absent'
    (Get-FileHash -LiteralPath $alternate).Hash | Should -Be $alternateHash
    (Get-FileHash -LiteralPath (Join-Path (Split-Path -Parent $updated.PreviousManifest) 'profiles/alternate.psd1')).Hash | Should -Be $alternateHash
  }

  It 'rejects duplicate IDs, product ownership, wrong namespaces and non-increasing versions without writes' -TestCases @(
    @{ Failure = 'Id'; Pattern = '*Duplicate catalog ID*' }, @{ Failure = 'Product'; Pattern = '*Duplicate package ownership*' },
    @{ Failure = 'Namespace'; Pattern = '*existing library namespace*' }, @{ Failure = 'Version'; Pattern = '*higher library version*' }
  ) {
    param($Failure, $Pattern)
    switch ($Failure) {
      Id { $script:NewDefinition.Operations[0].Id = 'app' }
      Product { $script:NewDefinition.Operations[0].PackageId = 'test.author.app' }
      Namespace { $script:NewDefinition.Id = 'other.library' }
      Version { $script:NewDefinition.Version = '0.1.0' }
    }
    { Add-RideLibraryOperation -Path $script:ProjectPath -Definition $script:NewDefinition -Confirm:$false } | Should -Throw $Pattern
    (Get-FileHash -LiteralPath (Join-Path $script:ProjectPath 'catalog/operations.psd1')).Hash | Should -Be $script:BeforeHash
    Test-Path -LiteralPath ($script:ProjectPath + '.history') | Should -BeFalse
  }

  It 'previews without project changes, staging, history or lock files' {
    Add-RideLibraryOperation -Path $script:ProjectPath -Definition $script:NewDefinition -WhatIf | Out-Null
    (Get-FileHash -LiteralPath (Join-Path $script:ProjectPath 'catalog/operations.psd1')).Hash | Should -Be $script:BeforeHash
    Test-Path -LiteralPath ($script:ProjectPath + '.history') | Should -BeFalse
    Test-Path -LiteralPath (Join-Path $script:ProjectPath '.ride-authoring.lock') | Should -BeFalse
    @(Get-ChildItem -LiteralPath $TestDrive -Directory -Filter '.ride-library-add-*').Count | Should -Be 0
  }

  It 'restores exact original metadata after a partial write failure' {
    $global:RideAppendFailureCalls = 0
    Mock Set-RideLibraryMetadataFile -ModuleName RIDE.LibraryAuthoring {
      $global:RideAppendFailureCalls++
      if ($global:RideAppendFailureCalls -eq 2) { throw 'Simulated profile publication failure.' }
      [IO.File]::Replace($Source, $Destination, [NullString]::Value)
    }
    try {
      { Add-RideLibraryOperation -Path $script:ProjectPath -Definition $script:NewDefinition -Confirm:$false } | Should -Throw '*publication failed*Previous metadata retained*'
      (Get-FileHash -LiteralPath (Join-Path $script:ProjectPath 'catalog/operations.psd1')).Hash | Should -Be $script:BeforeHash
      (Get-RideCatalogContext -Root $script:Root -Library $script:Project.Manifest).Libraries[0].Version | Should -Be '0.1.0'
      Test-Path -LiteralPath (Join-Path $script:ProjectPath '.ride-authoring.lock') | Should -BeFalse
    } finally { Remove-Variable RideAppendFailureCalls -Scope Global -ErrorAction SilentlyContinue }
  }

  It 'blocks metadata readers while a publication lock exists' {
    $lock = Join-Path $script:ProjectPath '.ride-authoring.lock'
    [IO.File]::WriteAllText($lock, 'Test-only publication marker')
    { Get-RideCatalogContext -Root $script:Root -Library $script:Project.Manifest } | Should -Throw '*authoring is in progress*'
    { Add-RideLibraryOperation -Path $script:ProjectPath -Definition $script:NewDefinition -Confirm:$false } | Should -Throw '*authoring is in progress*'
  }

  It 'retains recovery metadata and blocks readers when publication and rollback both fail' {
    $global:RideAppendFailureCalls = 0
    Mock Set-RideLibraryMetadataFile -ModuleName RIDE.LibraryAuthoring {
      $global:RideAppendFailureCalls++
      if ($global:RideAppendFailureCalls -ge 2) { throw 'Simulated publication and rollback failure.' }
      [IO.File]::Replace($Source, $Destination, [NullString]::Value)
    }
    try {
      { Add-RideLibraryOperation -Path $script:ProjectPath -Definition $script:NewDefinition -Confirm:$false -WarningAction SilentlyContinue } | Should -Throw '*publication failed*Previous metadata retained*'
      Test-Path -LiteralPath (Join-Path $script:ProjectPath '.ride-authoring.lock') | Should -BeTrue
      { Get-RideCatalogContext -Root $script:Root -Library $script:Project.Manifest } | Should -Throw '*authoring is in progress*'
      $previous = Get-ChildItem -LiteralPath ($script:ProjectPath + '.history') -Filter ride-library.psd1 -Recurse
      @($previous).Count | Should -Be 1
      (Get-RideCatalogContext -Root $script:Root -Library $previous.FullName).Libraries[0].CatalogSha256 | Should -Be $script:BeforeHash.ToLowerInvariant()
    } finally { Remove-Variable RideAppendFailureCalls -Scope Global -ErrorAction SilentlyContinue }
  }

  It 'guides addition with the existing namespace and a default version bump while skipping the license URL' {
    $global:RideAppendPrompt = @{ Index = 0; Responses = @('', '1', '1', 'second-app', 'Second App', 'Another fixture', '2', '1', '1', '1', '1', '1', 'https://publisher.example.invalid/second.exe', '2.0', 'second.exe', '', 'Second App', '/S', '/S', '', '', '', '', '1', '', '1') }
    Mock Read-Host {
      $state = $global:RideAppendPrompt
      if ($state.Index -ge $state.Responses.Count) { throw 'Unexpected Add prompt.' }
      $answer = $state.Responses[$state.Index]; $state.Index++; $answer
    }
    try {
      $updated = & $script:Helper -Path $script:ProjectPath -Add -Confirm:$false
      $updated.Version | Should -Be '0.1.1'
      $last = (Import-RideCatalogData -Path (Join-Path $script:ProjectPath 'catalog/operations.psd1')).Operations[-1]
      $last.License | Should -Be 'Unknown'
      $last.ContainsKey('LicenseUri') | Should -BeFalse
      $global:RideAppendPrompt.Index | Should -Be $global:RideAppendPrompt.Responses.Count
    } finally { Remove-Variable RideAppendPrompt -Scope Global -ErrorAction SilentlyContinue }
  }
}

Describe 'Authoring after an update in an existing console' {
  BeforeEach {
    $script:CacheRoot = Join-Path $TestDrive ('cached-checkout-' + [guid]::NewGuid().ToString('N'))
    foreach ($directory in @('modules', 'catalog', 'tools', 'profiles', 'components')) { $null = New-Item -ItemType Directory -Path (Join-Path $script:CacheRoot $directory) -Force }
    foreach ($module in @('RIDE.CatalogData', 'RIDE.LibrarySchema', 'RIDE.CatalogValidation', 'RIDE.Libraries', 'RIDE.LibraryAuthoring', 'RIDE.InstallerInspection')) {
      Copy-Item -LiteralPath (Join-Path $script:Root ('modules/' + $module + '.psm1')) -Destination (Join-Path $script:CacheRoot 'modules')
    }
    Copy-Item -LiteralPath (Join-Path $script:Root 'catalog/operations.psd1') -Destination (Join-Path $script:CacheRoot 'catalog')
    Copy-Item -LiteralPath (Join-Path $script:Root 'components/profiles') -Destination (Join-Path $script:CacheRoot 'components') -Recurse
    Copy-Item -LiteralPath $script:Helper -Destination (Join-Path $script:CacheRoot 'tools')
    $script:CachedHelper = Join-Path $script:CacheRoot 'tools/New-RideLibrary.ps1'
    $script:CachedSchema = Join-Path $script:CacheRoot 'modules/RIDE.LibrarySchema.psm1'
    $script:LatestSchema = [IO.File]::ReadAllText($script:CachedSchema)
    $global:RideCachedAuthoringPrompt = @{ Index = 0; Responses = @() }
    Mock Read-Host {
      $state = $global:RideCachedAuthoringPrompt
      if ($state.Index -ge $state.Responses.Count) { throw 'Unexpected prompt: the packaging choice did not advance.' }
      $answer = $state.Responses[$state.Index]; $state.Index++; $answer
    }
  }
  AfterEach {
    Remove-Variable RideCachedAuthoringPrompt -Scope Global -ErrorAction SilentlyContinue
    Get-Module | Where-Object { $_.Path -like ($script:CacheRoot + '\*') } | Remove-Module -Force
    foreach ($module in @('RIDE.CatalogData', 'RIDE.LibrarySchema', 'RIDE.CatalogValidation', 'RIDE.Libraries', 'RIDE.LibraryAuthoring')) {
      Import-Module (Join-Path $script:Root ('modules/' + $module + '.psm1')) -Force -Global
    }
  }

  It 'reloads a cached schema for read-only option discovery' {
    [IO.File]::WriteAllText($script:CachedSchema, ($script:LatestSchema -replace '(?m)^    ArchiveTypes = .*\r?\n', ''), [Text.UTF8Encoding]::new($false))
    Import-Module $script:CachedSchema -Force
    (Get-RideLibraryAuthoringOptions -Root $script:CacheRoot).ContainsKey('ArchiveTypes') | Should -BeFalse
    [IO.File]::WriteAllText($script:CachedSchema, $script:LatestSchema, [Text.UTF8Encoding]::new($false))
    $rows = @(& $script:CachedHelper -ShowOptions)
    ($rows | Where-Object Field -eq ArchiveTypes).Choices | Should -Be @('None', 'Zip')
    $global:RideCachedAuthoringPrompt.Index | Should -Be 0
  }

  It 'accepts packaging <Packaging> and publishes with cached pre-ZIP metadata refreshed' -TestCases @(
    @{ Packaging = ''; ArchiveType = '' }, @{ Packaging = 'Zip'; ArchiveType = 'Zip' }, @{ Packaging = '2'; ArchiveType = 'Zip' }
  ) {
    param($Packaging, $ArchiveType)
    [IO.File]::WriteAllText($script:CachedSchema, ($script:LatestSchema -replace '(?m)^    ArchiveTypes = .*\r?\n', ''), [Text.UTF8Encoding]::new($false))
    $validationPath = Join-Path $script:CacheRoot 'modules/RIDE.CatalogValidation.psm1'
    $latestValidation = [IO.File]::ReadAllText($validationPath)
    [IO.File]::WriteAllText($validationPath, $latestValidation.Replace('(exe|msi|zip)', '(exe|msi)'), [Text.UTF8Encoding]::new($false))
    foreach ($module in @('RIDE.LibrarySchema', 'RIDE.CatalogValidation', 'RIDE.Libraries', 'RIDE.LibraryAuthoring')) {
      Import-Module (Join-Path $script:CacheRoot ('modules/' + $module + '.psm1')) -Force
    }
    [IO.File]::WriteAllText($script:CachedSchema, $script:LatestSchema, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($validationPath, $latestValidation, [Text.UTF8Encoding]::new($false))
    # Blank packaging uses the direct-installer default; ZIP has two additional prompts.
    $zipAnswers = if ($ArchiveType -eq 'Zip') { @('setup.exe', '') } else { @() }
    $extension = if ($ArchiveType -eq 'Zip') { 'zip' } else { 'exe' }
    $global:RideCachedAuthoringPrompt.Responses = @('test.cache', '', '1', '1', 'app', 'Example App', 'Cache fixture', '2', '1', '1', $Packaging) +
      $zipAnswers + @('1', '1', "https://publisher.example.invalid/app.$extension", '1.2.3', "app.$extension", '', 'Example App', '/S', '/S', 'MIT', 'https://publisher.example.invalid/license', '', '', '1', '', '1')
    $project = & $script:CachedHelper -Path (Join-Path $script:CacheRoot 'new-library') -Confirm:$false
    $operation = (Import-PowerShellDataFile -LiteralPath (Join-Path $project.Path 'catalog/operations.psd1')).Operations[0]
    if ($ArchiveType) { $operation.ArchiveType | Should -Be $ArchiveType } else { $operation.ContainsKey('ArchiveType') | Should -BeFalse }
    $global:RideCachedAuthoringPrompt.Index | Should -Be $global:RideCachedAuthoringPrompt.Responses.Count
  }

  It 'stops before reading input for an empty packaging list' {
    [IO.File]::WriteAllText($script:CachedSchema, ($script:LatestSchema -replace "ArchiveTypes = @\('None', 'Zip'\)", 'ArchiveTypes = @()'), [Text.UTF8Encoding]::new($false))
    $global:RideCachedAuthoringPrompt.Responses = @('test.cache', '', '1', '1', 'app', 'Example App', 'Cache fixture', '2', '1', '1')
    $outputPath = Join-Path $script:CacheRoot 'no-library'
    { & $script:CachedHelper -Path $outputPath -Confirm:$false } | Should -Throw '*No valid choices*Download packaging*'
    $global:RideCachedAuthoringPrompt.Index | Should -Be 10
    Test-Path -LiteralPath $outputPath | Should -BeFalse
  }
}
