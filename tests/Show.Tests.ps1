<#
.SYNOPSIS
  Verify show pipeline binding and versioned inspection objects without Windows changes.
.DESCRIPTION
  Uses an isolated runner with the real show projection and ID resolver, synthetic
  catalog data and read-only state stubs. No operational handlers are loaded.
.EXAMPLE
  Invoke-Pester .\tests\Show.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  Version: Test fixture. Scratch files use TestDrive.
#>

BeforeAll {
  $script:Root = Split-Path -Parent $PSScriptRoot
  $script:IsolatedRoot = Join-Path $TestDrive 'show runner'
  $moduleDirectory = Join-Path $script:IsolatedRoot 'modules'
  $null = New-Item -ItemType Directory -Path $moduleDirectory, (Join-Path $script:IsolatedRoot 'catalog')
  Copy-Item -LiteralPath (Join-Path $script:Root 'ride.ps1') -Destination $script:IsolatedRoot
  foreach ($name in @('RIDE.CatalogData.psm1', 'RIDE.CatalogValidation.psm1', 'RIDE.Discovery.psm1', 'RIDE.SettingPresentation.psm1', 'RIDE.Libraries.psm1', 'RIDE.LibrarySchema.psm1')) {
    Copy-Item -LiteralPath (Join-Path $script:Root "modules/$name") -Destination $moduleDirectory
  }
  @'
@{
  SchemaVersion = 1
  Operations = @(
    @{ Id = 'package.alpha'; Name = 'Alpha'; Kind = 'Package'; Category = 'Software / Utilities'; Description = 'Alpha package'; Scope = 'Machine'; RequiresAdmin = $true; Actions = @('Get'); SupportedTargets = @('Fixture'); ProductUri = 'https://example.invalid/alpha' }
    @{ Id = 'windows.beta'; Name = 'Beta'; Kind = 'RegistryValue'; Category = 'Windows settings / Explorer'; Description = 'Beta setting'; Scope = 'User'; RequiresAdmin = $false; Actions = @('Get'); SupportedTargets = @('Fixture'); BaselineState = 'Enabled'; States = @{ Enabled = 1; Disabled = 0 } }
  )
  Groups = @(@{ Id = 'group.alpha'; Name = 'Alpha group'; Category = 'Software / Utilities'; Description = 'Group'; Members = @('package.alpha', 'windows.beta') })
}
'@ | Set-Content -LiteralPath (Join-Path $script:IsolatedRoot 'catalog/operations.psd1') -Encoding UTF8
  $tokens = $null; $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'modules/RIDE.Engine.psm1'), [ref]$tokens, [ref]$parseErrors)
  $definitions = $ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Show-RideOperation', 'Get-RideOperation')
  }, $false).Extent.Text -join "`n"
  $stubs = @'
Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1')
Import-Module (Join-Path $PSScriptRoot 'RIDE.Discovery.psm1')
Import-Module (Join-Path $PSScriptRoot 'RIDE.SettingPresentation.psm1')
Import-Module (Join-Path $PSScriptRoot 'RIDE.Libraries.psm1')
function Set-RideLibraryContext { param($Library) $script:Catalog = (Get-RideCatalogContext -Root (Split-Path -Parent $PSScriptRoot) -Library $Library).Catalog }
function Get-RideCatalog { $script:Catalog }
function Show-RideCatalog { param($View) Select-RideCatalogView -Catalog (Get-RideCatalog) -Rows @(Get-RideCatalogRows -Catalog (Get-RideCatalog)) -View $View }
function Resolve-RideLifecycleSelection { param($Operation, $Variant, [switch]$Removal) $copy = $Operation.Clone(); if ($Variant) { $copy.Variant = $Variant }; $copy }
function Get-RideCurrentState { param($Operation) [pscustomobject]@{ Present = $true; Exists = $true; Value = 0; ValueType = 'DWord' } }
function Get-RideCurrentValueText { param($Operation, $CurrentState) if ($Operation.Kind -eq 'Package') { 'Installed' } else { '0' } }
function Get-RideOperationValue { param($Operation, $State) $Operation.States[$State] }
function ConvertTo-RideDisplayValue { param($Value) [string]$Value }
function Get-RideSettingPresentation { param($Operation, [switch]$IncludeExecutionIdentity) [pscustomobject]@{ Scope = $Operation.Scope; RequiresAdmin = $Operation.RequiresAdmin } }
'@
  [IO.File]::WriteAllText((Join-Path $moduleDirectory 'RIDE.Engine.psm1'), ($stubs + "`n" + $definitions + "`nExport-ModuleMember -Function Set-RideLibraryContext,Show-RideOperation,Show-RideCatalog`n"), [Text.UTF8Encoding]::new($false))
  $script:Runner = Join-Path $script:IsolatedRoot 'ride.ps1'
}

AfterAll {
  $prefix = $script:IsolatedRoot + [IO.Path]::DirectorySeparatorChar
  Get-Module -All | Where-Object { $_.Path -and $_.Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } | Remove-Module -Force
}

Describe 'Show input and output pipelines' {
  It 'preserves positional and named ID syntax and returns selectable package fields' {
    $row = & $script:Runner show -Id package.alpha
    $row.SchemaVersion | Should -Be 1
    $row.PSObject.TypeNames | Should -Contain 'RIDE.ShowResult'
    $row.Id | Should -Be 'package.alpha'
    $row.Installed | Should -BeTrue
    $row = & $script:Runner show package.alpha | Select-Object Id, Name, Installed
    $row.Name | Should -Be 'Alpha'
    $row.Installed | Should -BeTrue
  }

  It 'accepts strings and Id-bearing objects in input order, including repeats' {
    $rows = @('package.alpha', [pscustomobject]@{ Id = 'windows.beta' }, 'PACKAGE.ALPHA') | & $script:Runner show
    @($rows).Count | Should -Be 3
    $rows.Id | Should -Be @('package.alpha', 'windows.beta', 'package.alpha')
    $rows[1].CurrentValue | Should -Be '0'
    $rows[1].BaselineValue | Should -Be '1'
  }

  It 'composes actual search and list output with show' {
    $rows = @(& $script:Runner search Alpha -View packages | & $script:Runner show)
    $rows.Count | Should -Be 1
    $rows[0].Id | Should -Be 'package.alpha'
    @(& $script:Runner list packages | & $script:Runner show).Id | Should -Be @('package.alpha')
  }

  It 'resolves external IDs from the selected library rather than trusting input metadata' {
    $libraryRoot = Join-Path $TestDrive 'selected library'
    $null = New-Item -ItemType Directory -Path $libraryRoot
    $library = Join-Path $libraryRoot 'ride-library.psd1'
    "@{ SchemaVersion=1; Id='example.library'; Version='0.1.0'; EngineApiVersion=1; Catalog='catalog.psd1'; Profiles=@() }" | Set-Content -LiteralPath $library -Encoding UTF8
    @'
@{
  SchemaVersion = 1
  Operations = @(@{
    Id='example.library.preference-marker'; Name='Library marker'; Description='Synthetic marker'; Kind='RegistryValue'; Handler='RegistryValue'
    Category='Windows settings / Library'; Scope='User'; RequiresAdmin=$false; SupportedTargets=@('Windows 11')
    Actions=@('Get','Test','Set','Restore'); RegistryPath='HKCU:\Software\RIDE\Test'; ValueName='Marker'; ValueType='DWord'
    States=@{Enabled=1;Disabled=0}; BaselineState='Disabled'; Rollback='Exact'
    TargetDefaults=@{'Windows 11'=@{DefaultValueExists=$false;DefaultValue=$null;EffectiveDefault='No marker'}}
  })
  Groups = @()
}
'@ | Set-Content -LiteralPath (Join-Path $libraryRoot 'catalog.psd1') -Encoding UTF8
    # Library loading validates the whole merged catalog. Start with an empty
    # built-in fixture and retain the isolated read-only observation stubs.
    $catalogPath = Join-Path $script:IsolatedRoot 'catalog/operations.psd1'
    $originalCatalog = [IO.File]::ReadAllText($catalogPath)
    try {
      '@{SchemaVersion=1;Operations=@();Groups=@()}' | Set-Content -LiteralPath $catalogPath -Encoding UTF8
      $rows = @(& $script:Runner search preference-marker -Library $library | & $script:Runner show -Library $library)
      $rows.Count | Should -Be 1
      $rows[0].Id | Should -Be 'example.library.preference-marker'
      $line = "& '$script:Runner' show -Library '$library' -InputObject example.library.pref"
      (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText | Should -Contain 'example.library.preference-marker'
    } finally {
      [IO.File]::WriteAllText($catalogPath, $originalCatalog, [Text.UTF8Encoding]::new($false))
    }
    $row = [pscustomobject]@{ Id = 'package.alpha'; Name = 'Untrusted name'; Installed = $false } | & $script:Runner show
    $row.Name | Should -Be 'Alpha'
    $row.Installed | Should -BeTrue
  }

  It 'returns nothing for an empty pipeline or a search with no matches' {
    @(@() | & $script:Runner show).Count | Should -Be 0
    @(& $script:Runner search no-such-entry | & $script:Runner show).Count | Should -Be 0
    { & $script:Runner show } | Should -Throw '*requires an operation or group ID*'
  }

  It 'rejects ambiguous explicit IDs and pipeline input' {
    { 'package.alpha' | & $script:Runner show windows.beta } | Should -Throw '*not both*'
    { @() | & $script:Runner show -Id package.alpha } | Should -Throw '*not both*'
    { & $script:Runner show package.alpha -InputObject 'windows.beta' } | Should -Throw '*not both*'
    { 'package.alpha' | & $script:Runner show -InputObject 'windows.beta' } | Should -Throw '*not both*'
  }

  It 'rejects malformed input without silently coercing it to an ID' {
    foreach ($inputValue in @($null, '', ' ', 42, [pscustomobject]@{ Name = 'Alpha' }, [pscustomobject]@{ Id = @('package.alpha', 'windows.beta') })) {
      { $inputValue | & $script:Runner show } | Should -Throw '*nonblank*Id*'
    }
  }

  It 'stops on unknown IDs and preserves objects already emitted' {
    $received = [Collections.Generic.List[object]]::new()
    { @('package.alpha', 'package.unknown', 'windows.beta') | & $script:Runner show | ForEach-Object { $received.Add($_) } } | Should -Throw '*Unknown operation or group ID*'
    $received.Count | Should -Be 1
    $received[0].Id | Should -Be 'package.alpha'
  }

  It 'forwards variants for each piped package and supports explicit InputObject' {
    $row = 'package.alpha' | & $script:Runner show -Variant portable
    $row.Variant | Should -Be 'portable'
    (& $script:Runner show -InputObject ([pscustomobject]@{ Id = 'package.alpha' })).Id | Should -Be 'package.alpha'
    { 'windows.beta' | & $script:Runner show -Variant portable } | Should -Throw '*Variant requires a package ID*'
  }

  It 'returns one group object with original member IDs and nested observations' {
    $rows = @(& $script:Runner show group.alpha)
    $rows.Count | Should -Be 1
    $rows[0].SchemaVersion | Should -Be 1
    $rows[0].Kind | Should -Be 'Group'
    $rows[0].Members | Should -Be @('package.alpha', 'windows.beta')
    $rows[0].MemberStates.Id | Should -Be $rows[0].Members
    $rows[0].MemberStates[0].CurrentValue | Should -Be 'Installed'
    $json = $rows | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $json.MemberStates.Count | Should -Be 2
    $json.MemberStates[1].CurrentValue | Should -Be '0'
  }

  It 'supports filtering, CSV export, and ordinary interactive display' {
    $rows = @('package.alpha', 'windows.beta') | & $script:Runner show | Where-Object Kind -eq Package
    $path = Join-Path $TestDrive 'packages.csv'
    $rows | Select-Object SchemaVersion, Id, Installed | Export-Csv -LiteralPath $path -NoTypeInformation
    (Import-Csv -LiteralPath $path).Id | Should -Be 'package.alpha'
    $text = & $script:Runner show package.alpha | Out-String
    $text | Should -Match 'Id\s+: package.alpha'
    $text | Should -Match 'Installed\s+: True'
  }

  It 'refuses pipeline input to other commands before engine dispatch' {
    foreach ($command in @('list', 'search', 'install', 'set', 'remove', 'apply', 'restore')) {
      { 'package.alpha' | & $script:Runner $command } | Should -Throw '*supported by show only*'
    }
  }

  It 'preserves version and help early exits' {
    (& $script:Runner -Version) | Should -Match '^\d+\.\d+\.\d+$'
    (& $script:Runner -Help | Out-String) | Should -Match 'SchemaVersion 1'
  }

  It 'completes show IDs using the same catalog for positional, named and InputObject values' {
    foreach ($suffix in @('show package.a', 'show -Id PACKAGE.A', 'show -InputObject package.a')) {
      $line = "& '$script:Runner' $suffix"
      $matches = @((TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText)
      $matches | Should -Contain 'package.alpha'
      @($matches | Sort-Object -Unique).Count | Should -Be $matches.Count
    }
  }
}
