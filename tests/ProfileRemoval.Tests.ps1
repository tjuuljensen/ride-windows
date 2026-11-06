<#
.SYNOPSIS
  Exercise explicit CLI profile removal with a dependent and its prerequisite.
.DESCRIPTION
  Uses the Windows engine, a synthetic catalog, mocked handlers and TestDrive
  journals. Each case starts with three packages installed.
.EXAMPLE
  Invoke-Pester ./tests/ProfileRemoval.Tests.ps1
.NOTES
  Windows PowerShell 5.1 and PowerShell 7 with Pester 5.
#>
Describe 'Explicit CLI profile removal' {
  BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repo 'modules/RIDE.Engine.psm1') -Force
    $script:runner = Join-Path $TestDrive 'ride.ps1'
    Copy-Item -LiteralPath (Join-Path $repo 'ride.ps1') -Destination $script:runner
  }

  BeforeEach {
    # Keep the real, mocked engine loaded. The CLI copy has no production modules beside it.
    Mock Import-Module {} -ParameterFilter { $Name -like '*RIDE.Engine.psm1' }
    $script:runs = Join-Path $TestDrive ([guid]::NewGuid().ToString())
    $script:profilePath = Join-Path $TestDrive 'removal.psd1'
    $script:installed = @{ 'package.alpha' = $true; 'package.beta' = $true; 'package.third' = $true }
    $script:uninstalls = [Collections.Generic.List[string]]::new()
    $packages = @(foreach ($id in $script:installed.Keys) {
      @{ Id = $id; Name = $id; Kind = 'Package'; Handler = 'Package'; Scope = 'User'; Actions = @('Uninstall')
         SelectedVariant = 'installed'; SupportedTargets = @('Windows 11') }
    })
    ($packages | Where-Object Id -eq 'package.beta').PrerequisitePackageId = 'package.alpha'
    $setting = @{ Id = 'setting.keep'; Kind = 'RegistryValue'; Handler = 'RegistryValue'; States = @{ Enabled = 1 } }
    $global:RideRemovalFixture = @{
      Catalog = @{ Operations = $packages + @($setting); Groups = @() }
      Installed = $script:installed
      Uninstalls = $script:uninstalls
      Runs = $script:runs
    }
    Mock Get-RideCatalog -ModuleName RIDE.Engine { $global:RideRemovalFixture.Catalog }
    Mock Get-RidePlatform -ModuleName RIDE.Engine { 'Windows 11' }
    Mock Get-RideStateRoot -ModuleName RIDE.Engine { Join-Path $global:RideRemovalFixture.Runs $Scope }
    Mock Get-RideInstalledPackage -ModuleName RIDE.Engine {
      [pscustomobject]@{ Present = $global:RideRemovalFixture.Installed[$Operation.Id]; DisplayVersion = '1' }
    }
    Mock Uninstall-RidePackage -ModuleName RIDE.Engine {
      $global:RideRemovalFixture.Uninstalls.Add($Operation.Id)
      $global:RideRemovalFixture.Installed[$Operation.Id] = $false
    }
    Mock Set-RideSettingState -ModuleName RIDE.Engine { throw 'Removal touched an ordinary setting.' }
  }

  AfterEach { Remove-Variable RideRemovalFixture -Scope Global }

  It 'previews and removes beta before alpha for profile order <First>, <Second>' -TestCases @(
    @{ First = 'alpha'; Second = 'beta' }
    @{ First = 'beta'; Second = 'alpha' }
  ) {
    param($First, $Second)
    @"
@{ SchemaVersion = 1; Operations = @(
  @{ Id = 'package.$First'; State = 'Present' }
  @{ Id = 'setting.keep'; State = 'Enabled' }
  @{ Id = 'package.$Second'; State = 'Present' }
) }
"@ | Set-Content -LiteralPath $script:profilePath

    $preview = & $script:runner remove -Profile $script:profilePath -WhatIf | Out-String -Width 240
    $preview | Should -Match '(?s)package\.beta.*package\.alpha'
    $script:uninstalls.Count | Should -Be 0
    Test-Path -LiteralPath $script:runs | Should -BeFalse

    & $script:runner remove -Profile $script:profilePath -Confirm:$false | Out-Null
    @($script:uninstalls.ToArray()) | Should -Be @('package.beta', 'package.alpha')
    $manifest = @(Get-ChildItem -LiteralPath $script:runs -Recurse -Filter '_manifest.json')
    $manifest.Count | Should -Be 1
    $journal = Get-Content -LiteralPath $manifest[0].FullName -Raw | ConvertFrom-Json
    @($journal.OperationProgress.OperationId) | Should -Be @('package.beta', 'package.alpha')
    @($journal.OperationProgress.Status) | Should -Be @('Completed', 'Completed')
    $script:installed['package.alpha'] | Should -BeFalse
    $script:installed['package.beta'] | Should -BeFalse
    $script:installed['package.third'] | Should -BeTrue
    Should -Invoke Set-RideSettingState -ModuleName RIDE.Engine -Exactly -Times 0
  }

  It 'rejects an unknown later profile entry before any removal or saved run' {
    "@{ SchemaVersion = 1; Operations = @(@{ Id = 'package.beta' }, @{ Id = 'package.unknown' }) }" |
      Set-Content -LiteralPath $script:profilePath
    { & $script:runner remove -Profile $script:profilePath -Confirm:$false } | Should -Throw '*unknown operation*package.unknown*'
    $script:uninstalls.Count | Should -Be 0
    $script:installed['package.alpha'] | Should -BeTrue
    $script:installed['package.beta'] | Should -BeTrue
    Test-Path -LiteralPath $script:runs | Should -BeFalse
  }
}
