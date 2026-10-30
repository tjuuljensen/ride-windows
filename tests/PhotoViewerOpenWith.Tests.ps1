<#
.SYNOPSIS
  Verify the pending Windows Photo Viewer Open with registration candidate.
.DESCRIPTION
  Checks catalog scope, explicit registration values and declared state matching
  without writing to the current user's registry or invoking Photo Viewer.
.EXAMPLE
  Invoke-Pester .\tests\PhotoViewerOpenWith.Tests.ps1
.NOTES
  Compatibility: Pester 5.7.1 on Windows PowerShell 5.1 and PowerShell 7.
  Prerequisites: Repository checkout; no elevation or Windows Photo Viewer needed.
  Recovery: No Windows state is changed by these tests.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-28: Cover the pending current-user registration candidate.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-RegistryValueSet.psm1') -Force
  $script:Operation = Get-RideOperation -Id 'windows.photo-viewer-openwith'
}

Describe 'Windows Photo Viewer Open with candidate' {
  It 'remains an unsupported Windows 11 candidate until native acceptance' {
    $script:Operation.SupportedTargets | Should -BeNullOrEmpty
    $script:Operation.CandidateTargets | Should -Contain 'Windows 11'
    $script:Operation.PendingAcceptance | Should -BeTrue
    $script:Operation.Scope | Should -Be 'User'
    $script:Operation.RequiresAdmin | Should -BeFalse
  }

  It 'writes only the declared HKCU application registration and does not choose defaults' {
    $script:Operation.RegistryValues.Count | Should -Be 6
    @($script:Operation.RegistryValues | Where-Object { $_.RegistryPath -notlike 'HKCU:\Software\Classes\Applications\photoviewer.dll*' }).Count | Should -Be 0
    @($script:Operation.RegistryValues | Where-Object { $_.RegistryPath -match '\\UserChoice|\\Classes\\(Paint\.Picture|giffile|jpegfile|pngfile)' }).Count | Should -Be 0
    $script:Operation.RegistryValues.Key | Should -Contain 'DropTargetClsid'
    $script:Operation.RegistryValues.Key | Should -Contain 'SupportedBmp'
    $script:Operation.RegistryValues.Key | Should -Contain 'SupportedGif'
    $script:Operation.RegistryValues.Key | Should -Contain 'SupportedJpg'
    $script:Operation.RegistryValues.Key | Should -Contain 'SupportedPng'
    $script:Operation.States.Registered.DropTargetClsid | Should -Be '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}'
    $script:Operation.LegacySelectors | Should -Contain 'AddPhotoViewerOpenWith'
    $script:Operation.LegacySelectors | Should -Contain 'RemovePhotoViewerOpenWith'
  }

  It 'matches only a complete registration and WindowsDefault removes every declared override' {
    $registered = Get-RideRegistryValueSetEffectiveDesiredState -Operation $script:Operation -State Registered
    $current = [pscustomobject]@{ Values = @($script:Operation.RegistryValues | ForEach-Object {
      [pscustomobject]@{
        Key = $_.Key
        Exists = $true
        Value = $registered[$_.Key]
        ValueType = $_.ValueType
        KeyExisted = $true
      }
    }) }
    Test-RideRegistryValueSetMatch -Operation $script:Operation -State Registered -CurrentState $current | Should -BeTrue
    $current.Values[2].Value = 'unexpected'
    Test-RideRegistryValueSetMatch -Operation $script:Operation -State Registered -CurrentState $current | Should -BeFalse
    $default = Get-RideRegistryValueSetEffectiveDesiredState -Operation $script:Operation -State WindowsDefault
    @($default.Values | Where-Object { $null -ne $_ }).Count | Should -Be 0
    @(Get-RideSingleOperationPlan -Id $script:Operation.Id -Action Unset)[0].State | Should -Be 'WindowsDefault'
  }
}
