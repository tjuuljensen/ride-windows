<#
.SYNOPSIS
  Verify the consolidated example, profile boundaries and historical recovery metadata.
.DESCRIPTION
  Loads declarative catalogs, expands profiles and adds metadata in TestDrive.
  Platform inspection is mocked. No Windows writer, installer or download runs.
.EXAMPLE
  Invoke-Pester .\tests\ExampleLibrary.Tests.ps1
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
  $script:Main = Join-Path $script:Root 'examples/library'
  $script:Manifest = Join-Path $script:Main 'ride-library.psd1'
  Import-Module (Join-Path $script:Root 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.LibraryAuthoring.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.Libraries.psm1') -Force
}

Describe 'One maintained example library' {
  BeforeEach {
    Set-RideLibraryContext -Library $script:Manifest
    Mock Get-RidePlatform -ModuleName RIDE.Engine { 'Windows 11' }
    Mock Get-RideCurrentState -ModuleName RIDE.Engine { throw 'Profile expansion must not inspect Windows.' }
    Mock Get-RideRecordedPackageSelection -ModuleName RIDE.Engine { $null }
  }
  AfterEach { Set-RideLibraryContext }

  It 'has one current manifest and three kinds under a shared namespace' {
    $current = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'examples') -Directory | Where-Object {
      Test-Path -LiteralPath (Join-Path $_.FullName 'ride-library.psd1')
    })
    $current.Count | Should -Be 1
    $current[0].Name | Should -Be 'library'
    $context = Get-RideCatalogContext -Root $script:Root -Library $script:Manifest
    $context.Libraries[0].Id | Should -Be 'example.library'
    $operations = @($context.Catalog.Operations | Where-Object Library)
    $operations.Id | Should -Be @('example.library.preference-marker', 'example.library.sha256-certutil', 'example.library.classic-msgames')
    $operations.Kind | Should -Be @('RegistryValue', 'RegistryValueSet', 'Package')
    (Import-PowerShellDataFile -LiteralPath $script:Manifest).Profiles.Count | Should -Be 3
  }

  It 'keeps the starter limited to the inert marker and settings free of packages' {
    $starter = @(Get-RidePlan -Profile (Get-RideProfile -Path (Join-Path $script:Main 'profiles/custom.psd1')))
    $starter.Operation.Id | Should -Be @('example.library.preference-marker')
    $settings = @(Get-RidePlan -Profile (Get-RideProfile -Path (Join-Path $script:Main 'profiles/settings.psd1')))
    $settings.Operation.Id | Should -Be @('example.library.preference-marker', 'example.library.sha256-certutil')
    $settings.Operation.Scope | Should -Be @('User', 'User')
    $settings.Operation.Kind | Should -Not -Contain 'Package'
    Should -Invoke Get-RideCurrentState -ModuleName RIDE.Engine -Times 0 -Exactly
  }

  It 'keeps packages separate and reuses built-in 7-Zip for installation and removal' {
    $profile = Get-RideProfile -Path (Join-Path $script:Main 'profiles/packages.psd1')
    $plan = @(Get-RidePlan -Profile $profile)
    $plan.Operation.Id | Should -Be @('package.7zip', 'example.library.classic-msgames')
    $plan.Operation.Kind | Should -Be @('Package', 'Package')
    $remove = @(Get-RidePlan -Profile $profile -Action Remove)
    $remove.Operation.Id | Should -Be @('package.7zip', 'example.library.classic-msgames')
    $remove.State | Should -Be @('Absent', 'Absent')
    @(Get-RideCatalog).Operations | Where-Object { $_.Library -and $_.PackageId -eq '7zip' } | Should -BeNullOrEmpty
  }

  It 'preserves games metadata except for identity and the corrected registered product name' {
    $original = (Import-RideCatalogData -Path (Join-Path $script:Root 'examples/recovery/games-library/0.1.1/catalog/operations.psd1')).Operations[0]
    $merged = (Import-RideCatalogData -Path (Join-Path $script:Main 'catalog/operations.psd1')).Operations | Where-Object Kind -eq Package
    $original = $original.Clone(); $merged = $merged.Clone()
    $merged.Id | Should -Be 'example.library.classic-msgames'
    $merged.PackageId | Should -Be 'example.library.classic-msgames'
    $merged.DisplayNamePattern | Should -Be '^Windows 7 Games for Windows 11, 10 and 8$'
    foreach ($entry in @($original, $merged)) { $entry.Remove('Id'); $entry.Remove('PackageId'); $entry.Remove('DisplayNamePattern') }
    $module = Get-Module RIDE.LibraryAuthoring
    $expected = & $module { param($data) ConvertTo-RideLibraryLiteral $data } $original
    $actual = & $module { param($data) ConvertTo-RideLibraryLiteral $data } $merged
    $actual | Should -BeExactly $expected
  }

  It 'keeps physical registry targets and the corrected icon/default command' {
    $setting = Get-RideOperation 'example.library.sha256-certutil'
    $setting.RegistryValues[0].RegistryPath | Should -Be 'HKCU:\Software\Classes\*\shell\SHA-256 with Certutil'
    $setting.RegistryValues[0].ValueName | Should -Be 'Icon'
    $setting.RegistryValues[1].ValueName | Should -BeExactly ''
    $setting.States.Enabled.Menu | Should -Be 'shell32.dll,-152'
    $setting.States.Enabled.Command | Should -Be 'cmd.exe /k certutil -hashfile "%1" SHA256'
    (Get-RideOperation 'example.library.preference-marker').RegistryPath | Should -Be 'HKCU:\Software\RIDE\Examples\Contoso'
  }

  It 'offers current IDs and profile paths through read-only completion' {
    $runner = Join-Path $script:Root 'ride.ps1'
    $prefix = "& '$runner' -Library '$script:Manifest' "
    $line = $prefix + 'show example.library.'
    (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText | Should -Contain 'example.library.classic-msgames'
    $line = $prefix + 'apply -Profile '
    $paths = (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText
    @($paths | Where-Object { $_ -like '*settings.psd1*' }).Count | Should -Be 1
    @($paths | Where-Object { $_ -like '*packages.psd1*' }).Count | Should -Be 1
    Should -Invoke Get-RideCurrentState -ModuleName RIDE.Engine -Times 0 -Exactly
  }

  It 'reloads the current resolver when an older library module is already imported' {
    $staleDirectory = Join-Path $TestDrive 'stale-module'
    $null = New-Item -ItemType Directory -Path $staleDirectory
    $staleSchema = Join-Path $staleDirectory 'RIDE.LibrarySchema.psm1'
    [IO.File]::WriteAllText($staleSchema, "function Get-RideLibraryAuthoringOptions { @{ Kinds = @('RegistryValue', 'Package') } }`nExport-ModuleMember -Function Get-RideLibraryAuthoringOptions`n", [Text.UTF8Encoding]::new($false))
    $staleModule = Join-Path $staleDirectory 'RIDE.Libraries.psm1'
    [IO.File]::WriteAllText($staleModule, "function Get-RideCatalogContext { throw 'Stale library resolver was used.' }`nExport-ModuleMember -Function Get-RideCatalogContext`n", [Text.UTF8Encoding]::new($false))
    $runner = Join-Path $script:Root 'ride.ps1'
    $probePath = Join-Path $TestDrive 'probe-resolver.ps1'
    $probe = "Import-Module '$staleSchema' -Force`nImport-Module '$staleModule' -Force`n& '$runner' list -Library '$script:Manifest' | Out-Null`nWrite-Output 'Current resolver loaded'`n"
    [IO.File]::WriteAllText($probePath, $probe, [Text.UTF8Encoding]::new($false))
    $shell = Join-Path $PSHOME $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })
    $stdout = Join-Path $TestDrive 'resolver-stdout.txt'; $stderr = Join-Path $TestDrive 'resolver-stderr.txt'
    $process = Start-Process -FilePath $shell -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $probePath + '"')) -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if ($process.ExitCode -ne 0) { throw ('Resolver probe failed: ' + [IO.File]::ReadAllText($stderr)) }
    [IO.File]::ReadAllText($stdout) | Should -Match 'Current resolver loaded'
  }

  It 'supports Add on a copy while preserving the two optional profiles and groups' {
    $copy = Join-Path $TestDrive 'copied-library'
    Copy-Item -LiteralPath $script:Main -Destination $copy -Recurse
    $settings = Join-Path $copy 'profiles/settings.psd1'; $packages = Join-Path $copy 'profiles/packages.psd1'
    $settingsHash = (Get-FileHash -LiteralPath $settings).Hash; $packagesHash = (Get-FileHash -LiteralPath $packages).Hash
    $definition = @{
      Id = 'example.library'; Version = '0.1.2'; Operations = @(
        @{
          Id = 'added-marker'; Kind = 'RegistryValue'; Name = 'Added inert marker'; Description = 'Metadata-only test fixture.'
          Scope = 'User'; SupportedTargets = @('Windows 11'); RegistryPath = 'HKCU:\Software\RIDE\ExampleTests'
          ValueName = 'Marker'; ValueType = 'DWord'; States = @{ Enabled = 1; WindowsDefault = $null }; BaselineState = 'WindowsDefault'
          TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $false; DefaultValue = $null; EffectiveDefault = 'No test marker' } }
        }
      )
    }
    $updated = Add-RideLibraryOperation -Path $copy -Definition $definition -Confirm:$false
    (Import-PowerShellDataFile -LiteralPath $updated.Profile).Operations.Id | Should -Be @('example.library.preference-marker', 'example.library.added-marker')
    (Get-FileHash -LiteralPath $settings).Hash | Should -Be $settingsHash
    (Get-FileHash -LiteralPath $packages).Hash | Should -Be $packagesHash
    (Import-RideCatalogData -Path (Join-Path $copy 'catalog/operations.psd1')).Groups[0].Members | Should -Be @('package.7zip')
    (Get-RideCatalogContext -Root $script:Root -Library $updated.PreviousManifest).Libraries[0].Version | Should -Be '0.1.1'
  }

  It 'resolves the retained <Id> <Version> identity separately from the new namespace' -TestCases @(
    @{ Relative = 'contoso/0.1.0'; Id = 'example.contoso'; Version = '0.1.0' },
    @{ Relative = 'games-library/0.1.0'; Id = 'custom.games'; Version = '0.1.0' },
    @{ Relative = 'games-library/0.1.1'; Id = 'custom.games'; Version = '0.1.1' }
  ) {
    param($Relative, $Id, $Version)
    $context = Get-RideCatalogContext -Root $script:Root -Library (Join-Path $script:Root ('examples/recovery/' + $Relative + '/ride-library.psd1'))
    $context.Libraries[0].Id | Should -Be $Id
    $context.Libraries[0].Version | Should -Be $Version
    @($context.Catalog.Operations | Where-Object { $_.Id -like 'example.library.*' }).Count | Should -Be 0
  }
}
