<#
.SYNOPSIS
  Verify local libraries, completion and recovery without changing Windows.
.DESCRIPTION
  Uses TestDrive metadata copies, mocked handlers and isolated state files.
.EXAMPLE
  Invoke-Pester .\tests\Libraries.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
  No installer, real registry writer or network source is invoked.
  Copied runner modules are unloaded when their isolated scenario finishes.
#>

BeforeAll {
  $script:Root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Root 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.Libraries.psm1') -Force
  $script:Runner = Join-Path $script:Root 'ride.ps1'
  function Write-LibraryFixture([string] $Path, [string] $Text) {
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
  }
  function Replace-LibraryFixture([string] $Path, [string] $From, [string] $To) {
    Write-LibraryFixture $Path ([IO.File]::ReadAllText($Path).Replace($From, $To))
  }
  function Add-LibraryPackageFixture([switch] $DuplicateProduct) {
    # Clone reviewed metadata only for mocked tests; never install the fixture.
    $source = [IO.File]::ReadAllText((Join-Path $script:Root 'catalog/operations.psd1'))
    $entry = [regex]::Match($source, "(?s)    @\{\r?\n      Id = 'package.7zip'.*?\r?\n    \}").Value
    if (-not $entry) { throw 'Cannot locate package fixture metadata.' }
    $entry = $entry.Replace("Id = 'package.7zip'", "Id = 'example.contoso.package-fixture'")
    if (-not $DuplicateProduct) { $entry = $entry.Replace("PackageId = '7zip'", "PackageId = 'contoso-package-fixture'") }
    Replace-LibraryFixture $script:CatalogFile '  Operations = @(' ("  Operations = @(`n" + $entry)
  }
}

Describe 'RIDE metadata libraries' {
  BeforeEach {
    $script:LibraryDirectory = Join-Path $TestDrive ('library ' + [guid]::NewGuid().ToString('N'))
    # The historical starter is a focused fixture for published-ID recovery.
    Copy-Item -LiteralPath (Join-Path $script:Root 'examples/recovery/contoso/0.1.0') -Destination $script:LibraryDirectory -Recurse
    $script:Manifest = Join-Path $script:LibraryDirectory 'ride-library.psd1'
    $script:CatalogFile = Join-Path $script:LibraryDirectory 'catalog/operations.psd1'
    $script:ProfileFile = Join-Path $script:LibraryDirectory 'profiles/workstation.psd1'
    Set-RideLibraryContext
  }

  AfterEach { Set-RideLibraryContext }

  Describe 'Declarative library resolution' {
    It 'loads a library outside the checkout and resolves built-in package references' {
      $context = Get-RideCatalogContext -Root $script:Root -Library $script:Manifest
      $external = $context.Catalog.Operations | Where-Object Id -eq 'example.contoso.preference-marker'
      $external.Library.Id | Should -Be 'example.contoso'
      $external.Library.CatalogSha256 | Should -Match '^[a-f0-9]{64}$'
      $context.Libraries[0].Version | Should -Be '0.1.0'
      $context.ProfileFiles.FullName | Should -Contain $script:ProfileFile
      Set-RideLibraryContext -Library $script:Manifest
      $plan = @(Get-RidePlan -Profile (Get-RideProfile -Path $script:ProfileFile))
      $plan.Operation.Id | Should -Be @('example.contoso.preference-marker', 'package.7zip')
      @(Get-RidePlan -Profile (Get-RideProfile -Path $script:ProfileFile) -Action Remove).Operation.Id | Should -Be @('package.7zip')
    }

    It 'lists the declared external profile and resets library selection between calls' {
      Set-RideLibraryContext -Library $script:Manifest
      @(Show-RideCatalog profiles).Path | Should -Contain $script:ProfileFile
      Set-RideLibraryContext
      { Get-RideOperation 'example.contoso.preference-marker' } | Should -Throw '*Unknown operation*'
    }

    It 'rejects duplicate manifest selection and duplicate library identity' {
      { Get-RideCatalogContext -Root $script:Root -Library @($script:Manifest, $script:Manifest) } | Should -Throw '*Duplicate library selection*'
      $otherDirectory = Join-Path $TestDrive 'duplicate-library'
      Copy-Item -LiteralPath $script:LibraryDirectory -Destination $otherDirectory -Recurse
      { Get-RideCatalogContext -Root $script:Root -Library @($script:Manifest, (Join-Path $otherDirectory 'ride-library.psd1')) } | Should -Throw '*Duplicate library ID*'
    }

    It 'rejects an incompatible API or schema before selecting it' {
      Replace-LibraryFixture $script:Manifest 'EngineApiVersion = 1' 'EngineApiVersion = 2'
      { Set-RideLibraryContext -Library $script:Manifest } | Should -Throw '*Unsupported library schema or engine API*'
      (Get-RideCatalog).Operations.Id | Should -Not -Contain 'example.contoso.preference-marker'
    }

    It 'rejects executable manifest data without running it' {
      $sentinel = Join-Path $TestDrive 'executed.txt'
      Write-LibraryFixture $script:Manifest ("New-Item -ItemType File -Path '" + $sentinel + "'; @{ SchemaVersion = 1 }")
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*Invalid declarative library data*'
      Test-Path -LiteralPath $sentinel | Should -BeFalse
    }

    It 'rejects executable catalog expressions and executable profile data' {
      Replace-LibraryFixture $script:CatalogFile 'Enabled = 1' 'Enabled = (Get-Process)'
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw
      Copy-Item -LiteralPath (Join-Path $script:Root 'examples/recovery/contoso/0.1.0/catalog/operations.psd1') -Destination $script:CatalogFile -Force
      Write-LibraryFixture $script:ProfileFile 'Get-Process; @{ SchemaVersion = 1 }'
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*Invalid declarative library data*'
    }

    It 'rejects undeclared manifest fields and unsupported custom handler modules' {
      Replace-LibraryFixture $script:Manifest 'SchemaVersion = 1' "SchemaVersion = 1; Modules = @('evil.psm1')"
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*Unsupported library manifest field*'
    }

    It 'rejects escaping paths and unresolved group or profile references' {
      Replace-LibraryFixture $script:Manifest "Catalog = 'catalog/operations.psd1'" "Catalog = '../operations.psd1'"
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*relative files inside the library*'
      Replace-LibraryFixture $script:Manifest "Catalog = '../operations.psd1'" "Catalog = 'catalog/operations.psd1'"
      Replace-LibraryFixture $script:CatalogFile "Members = @('package.7zip')" "Members = @('package.missing')"
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*Unknown member*'
      Replace-LibraryFixture $script:CatalogFile "Members = @('package.missing')" "Members = @('package.7zip')"
      Replace-LibraryFixture $script:ProfileFile 'example.contoso.preference-marker' 'example.contoso.missing'
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*unknown ID*'
    }

    It 'rejects duplicate catalog IDs and attempts to override a published ID' {
      Replace-LibraryFixture $script:CatalogFile "Id = 'example.contoso.utilities'" "Id = 'example.contoso.preference-marker'"
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*Duplicate catalog ID*'
      Replace-LibraryFixture $script:CatalogFile "Id = 'example.contoso.preference-marker'" "Id = 'windows.show-known-extensions'"
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*library prefix*'
    }

    It 'rejects scope mismatches and invalid supplied documentation links' {
      Replace-LibraryFixture $script:CatalogFile 'RequiresAdmin = $false' 'RequiresAdmin = $true'
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*scope/elevation*'
      Replace-LibraryFixture $script:CatalogFile 'RequiresAdmin = $true' 'RequiresAdmin = $false'
      Replace-LibraryFixture $script:CatalogFile 'https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types' 'http://example.invalid/registry'
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*Microsoft HTTPS documentation*'
    }

    It 'preserves the old active context if a new selection fails' {
      Set-RideLibraryContext -Library $script:Manifest
      Replace-LibraryFixture $script:Manifest "Version = '0.1.0'" "Version = 'invalid'"
      { Set-RideLibraryContext -Library $script:Manifest } | Should -Throw '*three-part version*'
      (Get-RideOperation 'example.contoso.preference-marker').Library.Version | Should -Be '0.1.0'
    }

    It 'accepts external package metadata and rejects duplicate product ownership' {
      Add-LibraryPackageFixture -DuplicateProduct
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*Duplicate package ownership*'
      Replace-LibraryFixture $script:CatalogFile "PackageId = '7zip'" "PackageId = 'contoso-package-fixture'"
      $context = Get-RideCatalogContext -Root $script:Root -Library $script:Manifest
      ($context.Catalog.Operations | Where-Object Id -eq 'example.contoso.package-fixture').Library.Handler | Should -Be 'Package'
    }

    It 'rejects typed registry states that do not match the declared value kind' {
      Replace-LibraryFixture $script:CatalogFile 'Enabled = 1' "Enabled = 'invalid DWORD'"
      { Get-RideCatalogContext -Root $script:Root -Library $script:Manifest } | Should -Throw '*Invalid registry state value*'
    }

    It 'loads literal manifest and profile paths containing brackets' {
      $literalDirectory = Join-Path $TestDrive 'library [literal]'
      Copy-Item -LiteralPath $script:LibraryDirectory -Destination $literalDirectory -Recurse
      Set-RideLibraryContext -Library (Join-Path $literalDirectory 'ride-library.psd1')
      $profile = Get-RideProfile -Path (Join-Path $literalDirectory 'profiles/workstation.psd1')
      @(Get-RidePlan -Profile $profile).Count | Should -Be 2
    }

    It 'resolves references across all selected libraries before validation' {
      $partnerDirectory = Join-Path $TestDrive 'partner'
      Copy-Item -LiteralPath $script:LibraryDirectory -Destination $partnerDirectory -Recurse
      $originalCatalog = $script:CatalogFile
      try {
        $script:CatalogFile = Join-Path $partnerDirectory 'catalog/operations.psd1'
        Add-LibraryPackageFixture
        Replace-LibraryFixture $script:CatalogFile 'example.contoso' 'example.partner'
      }
      finally { $script:CatalogFile = $originalCatalog }
      $partnerManifest = Join-Path $partnerDirectory 'ride-library.psd1'
      Replace-LibraryFixture $partnerManifest 'example.contoso' 'example.partner'
      Replace-LibraryFixture (Join-Path $partnerDirectory 'profiles/workstation.psd1') 'example.contoso' 'example.partner'
      Replace-LibraryFixture $script:CatalogFile "Members = @('package.7zip')" "Members = @('example.partner.package-fixture')"
      Set-RideLibraryContext -Library @($script:Manifest, $partnerManifest)
      $plan = @(Get-RidePlan -Profile (Get-RideProfile -Path $script:ProfileFile))
      $plan.Operation.Id | Should -Be @('example.contoso.preference-marker', 'example.partner.package-fixture')
    }
  }

  Describe 'Library search, completion and reference tools' {
    It 'completes module views from the resolved catalog supplied to execution' {
      Import-Module (Join-Path $script:Root 'modules/RIDE.Discovery.psm1') -Force
      $context = Get-RideCatalogContext -Root $script:Root -Library $script:Manifest
      $completer = (Get-Command Find-RideCatalog).Parameters.View.Attributes |
        Where-Object { $_ -is [Management.Automation.ArgumentCompleterAttribute] } | Select-Object -First 1
      @(& $completer.ScriptBlock 'Find-RideCatalog' 'View' 'library' $null @{ Catalog = $context.Catalog }).CompletionText |
        Should -Contain 'library-examples'
    }

    It 'searches external metadata in a runner copy with no engine or handlers' {
      $isolated = Join-Path $TestDrive 'isolated'
      New-Item -ItemType Directory -Path (Join-Path $isolated 'modules'), (Join-Path $isolated 'catalog'), (Join-Path $isolated 'profiles') | Out-Null
      Copy-Item -LiteralPath $script:Runner -Destination $isolated
      Copy-Item -LiteralPath (Join-Path $script:Root 'catalog/operations.psd1') -Destination (Join-Path $isolated 'catalog/operations.psd1')
      foreach ($module in @('RIDE.CatalogData.psm1', 'RIDE.CatalogValidation.psm1', 'RIDE.LibrarySchema.psm1', 'RIDE.Libraries.psm1', 'RIDE.Discovery.psm1', 'RIDE.SettingPresentation.psm1')) {
        Copy-Item -LiteralPath (Join-Path $script:Root "modules/$module") -Destination (Join-Path $isolated 'modules')
      }
      try {
        $result = @(& (Join-Path $isolated 'ride.ps1') search PreferenceMarker -Library $script:Manifest)
        $result.Id | Should -Be @('example.contoso.preference-marker')
        $result.MatchedFields | Should -Contain 'ValueName'
        Test-Path -LiteralPath (Join-Path $isolated 'modules/RIDE.Engine.psm1') | Should -BeFalse
      }
      finally {
        $modulePrefix = $isolated + [IO.Path]::DirectorySeparatorChar
        Get-Module -All | Where-Object {
          $_.Path -and $_.Path.StartsWith($modulePrefix, [StringComparison]::OrdinalIgnoreCase)
        } | Remove-Module -Force
      }
    }

    It 'completes selected external IDs, states, categories and profile paths containing spaces' {
      $prefix = "& '$script:Runner' -Library '$script:Manifest' "
      $line = $prefix + 'show example.contoso.p'
      (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText | Should -Contain 'example.contoso.preference-marker'
      $line = $prefix + 'set example.contoso.preference-marker -State E'
      (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText | Should -Contain 'Enabled'
      $line = $prefix + 'search marker -View library'
      (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText | Should -Contain 'library-examples'
      $line = $prefix + 'plan -Profile workstation'
      $matches = (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText
      @($matches | Where-Object { $_ -like '*library *workstation.psd1*' }).Count | Should -Be 1
    }

    It 'fails quietly during completion for an unavailable selected manifest' {
      $line = "& '$script:Runner' -Library '$TestDrive/missing.psd1' show example.contoso.p"
      { TabExpansion2 $line $line.Length | Out-Null } | Should -Not -Throw
    }

    It 'completes manifest paths using ordinary filesystem completion' {
      $line = "& '$script:Runner' -Library '$script:LibraryDirectory\ride-"
      @((TabExpansion2 $line $line.Length).CompletionMatches.CompletionText | Where-Object { $_ -like '*ride-library.psd1*' }).Count | Should -BeGreaterThan 0
    }

    It 'validates and exports selected libraries without overwriting the built-in reference' {
      { & (Join-Path $script:Root 'tools/validate.ps1') -Root $script:Root -Library $script:Manifest | Out-Null } | Should -Not -Throw
      $reference = Join-Path $TestDrive 'external-reference.md'
      & (Join-Path $script:Root 'tools/Export-RideCatalog.ps1') -Root $script:Root -Library $script:Manifest -OutputPath $reference | Out-Null
      [IO.File]::ReadAllText($reference) | Should -Match 'example.contoso.preference-marker'
      { & (Join-Path $script:Root 'tools/Export-RideCatalog.ps1') -Root $script:Root -Library $script:Manifest -OutputPath $reference -Check | Out-Null } | Should -Not -Throw
      { & (Join-Path $script:Root 'tools/Export-RideCatalog.ps1') -Root $script:Root -Library $script:Manifest | Out-Null } | Should -Throw '*require -OutputPath*'
      { & (Join-Path $script:Root 'tools/Export-RideCatalog.ps1') -Root $script:Root -Library $script:Manifest -OutputPath (Join-Path $script:Root 'docs/OPERATIONS.md') | Out-Null } | Should -Throw '*separate output file*'
    }
  }

  Describe 'External setting lifecycle and recovery identity' {
    BeforeEach {
      Set-RideLibraryContext -Library $script:Manifest
      $script:StateDirectory = Join-Path $TestDrive ('state-' + [guid]::NewGuid().ToString('N'))
      New-Item -ItemType Directory -Path $script:StateDirectory | Out-Null
      Mock -ModuleName RIDE.Engine Get-RidePlatform { 'Windows 11' }
      Mock -ModuleName RIDE.Engine Test-RideAdministrator { $true }
      Mock -ModuleName RIDE.Engine Get-RideStateRoot { if ($Scope -eq 'User') { $script:StateDirectory } else { Join-Path $script:StateDirectory 'machine-state' } }
      Mock -ModuleName RIDE.Engine Initialize-RideStateRoot {
        $root=if ($Scope -eq 'User') { $script:StateDirectory } else { Join-Path $script:StateDirectory 'machine-state' }
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $root
      }
      Mock -ModuleName RIDE.Engine Get-Item { $null }
      $script:LibraryCurrent = [pscustomobject]@{ Exists = $true; Value = 17; ValueType = 'DWord' }
      Mock -ModuleName RIDE.Engine Get-RideCurrentState { $script:LibraryCurrent }
      Mock -ModuleName RIDE.Engine Set-RideSettingState {
        $script:LibraryCurrent = [pscustomobject]@{ Exists = ($null -ne $Value); Value = $Value; ValueType = 'DWord' }
      }
      Mock -ModuleName RIDE.Engine Restore-RideSettingState {
        $script:LibraryCurrent = [pscustomobject]@{ Exists = $Snapshot.Exists; Value = $Snapshot.Value; ValueType = $Snapshot.ValueType }
      }
    }

    It 'previews without saving state, applies once, then restores the captured value' {
      $plan = @(Get-RideSingleOperationPlan -Id 'example.contoso.preference-marker' -Action Set -State Enabled)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Should -Invoke -ModuleName RIDE.Engine Initialize-RideStateRoot -Times 0 -Exactly
      Should -Invoke -ModuleName RIDE.Engine Set-RideSettingState -Times 0 -Exactly
      $messages = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $runId = ([string]($messages | Where-Object { $_ -like 'Run ID:*' })).Substring(8)
      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke -ModuleName RIDE.Engine Set-RideSettingState -Times 1 -Exactly
      $record = Get-Content -LiteralPath (Join-Path $script:StateDirectory "$runId/example.contoso.preference-marker.json") -Raw | ConvertFrom-Json
      $record.SchemaVersion | Should -Be 2
      $record.Snapshot.Value | Should -Be 17
      $record.Library.Handler | Should -Be 'RegistryValue'
      $manifestRecord = Get-Content -LiteralPath (Join-Path $script:StateDirectory "$runId/_manifest.json") -Raw | ConvertFrom-Json
      $manifestRecord.SchemaVersion | Should -Be 2
      @($manifestRecord.Libraries).Count | Should -Be 1
      $manifestRecord.Libraries[0].Id | Should -Be 'example.contoso'
      Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
      Should -Invoke -ModuleName RIDE.Engine Restore-RideSettingState -Times 0 -Exactly
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      $script:LibraryCurrent.Value | Should -Be 17
    }

    It 'retains captured state after a handler failure and reports the run ID' {
      Mock -ModuleName RIDE.Engine Set-RideSettingState { throw 'simulated external setting failure' }
      $plan = @(Get-RideSingleOperationPlan -Id 'example.contoso.preference-marker' -Action Set -State Enabled)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state: example.contoso.preference-marker*simulated external setting failure*'
      @(Get-ChildItem -LiteralPath $script:StateDirectory -Recurse -Filter 'example.contoso.preference-marker.json').Count | Should -Be 1
    }

    It 'uses the built-in package lifecycle and recovers prior presence through mocks' {
      Add-LibraryPackageFixture
      Set-RideLibraryContext -Library $script:Manifest
      $script:PackageCurrent = [pscustomobject]@{ Present = $false; DisplayVersion = $null }
      Mock -ModuleName RIDE.Engine Get-RideCurrentState { $script:PackageCurrent }
      Mock -ModuleName RIDE.Engine Get-RideInstalledPackage { $script:PackageCurrent }
      Mock -ModuleName RIDE.Engine Install-RidePackage { $script:PackageCurrent = [pscustomobject]@{ Present = $true; DisplayVersion = 'fixture-version' } }
      Mock -ModuleName RIDE.Engine Uninstall-RidePackage { $script:PackageCurrent = [pscustomobject]@{ Present = $false; DisplayVersion = $null } }
      $plan = @(Get-RideSingleOperationPlan -Id 'example.contoso.package-fixture' -Action Install)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Should -Invoke -ModuleName RIDE.Engine Install-RidePackage -Times 0 -Exactly
      $messages = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $runId = ([string]($messages | Where-Object { $_ -like 'Run ID:*' })).Substring(8)
      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke -ModuleName RIDE.Engine Install-RidePackage -Times 1 -Exactly
      Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
      Should -Invoke -ModuleName RIDE.Engine Uninstall-RidePackage -Times 0 -Exactly
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      $script:PackageCurrent.Present | Should -BeFalse
      $plan = @(Get-RideSingleOperationPlan -Id 'example.contoso.package-fixture' -Action Remove)
      $plan.State | Should -Be 'Absent'
    }

    It 'rejects a missing library before restoring any earlier built-in record' {
      InModuleScope RIDE.Engine {
        $external = Get-RideOperation 'example.contoso.preference-marker'
        $builtin = Get-RideOperation 'windows.show-known-extensions'
        Save-RideOperationSnapshot -RunId '11111111111111111111111111111111' -Operation $external -CurrentState (Get-RideCurrentState -Operation $external)
        Save-RideOperationSnapshot -RunId '11111111111111111111111111111111' -Operation $builtin -CurrentState (Get-RideCurrentState -Operation $builtin)
      }
      Set-RideLibraryContext
      { Restore-RideRun -RunId '11111111111111111111111111111111' -Confirm:$false } | Should -Throw '*original library*'
      Should -Invoke -ModuleName RIDE.Engine Restore-RideSettingState -Times 0 -Exactly
    }

    It 'retains an optional recovery-information link when the original library is unavailable' {
      Replace-LibraryFixture $script:CatalogFile "Rollback = 'Exact'" "Rollback = 'Exact'; RecoveryUri = 'https://example.invalid/recovery'"
      Set-RideLibraryContext -Library $script:Manifest
      InModuleScope RIDE.Engine {
        $operation = Get-RideOperation 'example.contoso.preference-marker'
        Save-RideOperationSnapshot -RunId '33333333333333333333333333333333' -Operation $operation -CurrentState (Get-RideCurrentState -Operation $operation)
      }
      Set-RideLibraryContext
      { Restore-RideRun -RunId '33333333333333333333333333333333' -Confirm:$false } | Should -Throw '*Recovery information: https://example.invalid/recovery*'
      Should -Invoke -ModuleName RIDE.Engine Restore-RideSettingState -Times 0 -Exactly
    }

    It 'rejects version changes and same-version catalog edits while allowing relocation' {
      InModuleScope RIDE.Engine {
        $operation = Get-RideOperation 'example.contoso.preference-marker'
        Save-RideOperationSnapshot -RunId '22222222222222222222222222222222' -Operation $operation -CurrentState (Get-RideCurrentState -Operation $operation)
      }
      Replace-LibraryFixture $script:Manifest "Version = '0.1.0'" "Version = '0.2.0'"
      Set-RideLibraryContext -Library $script:Manifest
      { Restore-RideRun -RunId '22222222222222222222222222222222' -Confirm:$false } | Should -Throw '*recovery mismatch (Version)*'
      Replace-LibraryFixture $script:Manifest "Version = '0.2.0'" "Version = '0.1.0'"
      Replace-LibraryFixture $script:CatalogFile 'Enabled = 1' 'Enabled = 2'
      Set-RideLibraryContext -Library $script:Manifest
      { Restore-RideRun -RunId '22222222222222222222222222222222' -Confirm:$false } | Should -Throw '*recovery mismatch (CatalogSha256)*'
      Should -Invoke -ModuleName RIDE.Engine Restore-RideSettingState -Times 0 -Exactly
      Replace-LibraryFixture $script:CatalogFile 'Enabled = 2' 'Enabled = 1'
      $relocated = Join-Path $TestDrive 'relocated library'
      Copy-Item -LiteralPath $script:LibraryDirectory -Destination $relocated -Recurse
      Set-RideLibraryContext -Library (Join-Path $relocated 'ride-library.psd1')
      Restore-RideRun -RunId '22222222222222222222222222222222' -Confirm:$false | Out-Null
      Should -Invoke -ModuleName RIDE.Engine Restore-RideSettingState -Times 1 -Exactly
    }
  }
}
