<#
.SYNOPSIS
  Verify separate conditional media policy mappings, scopes and recovery capture.
.DESCRIPTION
  Metadata and mocked registry/engine checks only. TestDrive contains saved runs;
  no player, license, network, real registry, package or disposable VM is used.
.EXAMPLE
  Invoke-Pester ./tests/MediaPolicies.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Cover radio/WMDRM conditional policies and local capture.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
}
Describe 'Conditional media policies' {
  It 'keeps <Id> scope, policy inversion and legacy removal separate' -ForEach @(
    @{ Id = 'windows.media-radio-preset-retrieval-policy'; Scope = 'User'; Root = 'HKCU:'; Admin = $false; Value = 'PreventRadioPresetsRetrieval' },
    @{ Id = 'windows.media-drm-online-access-policy'; Scope = 'Machine'; Root = 'HKLM:'; Admin = $true; Value = 'DisableOnline' }
  ) {
    $op = Get-RideOperation $Id
    $op.Scope | Should -Be $Scope
    $op.RequiresAdmin | Should -Be $Admin
    $op.RegistryPath | Should -BeLike ($Root + '*')
    $op.ValueName | Should -Be $Value
    $op.ValueType | Should -Be 'DWord'
    $op.States.Blocked | Should -Be 1
    $op.States.PolicyDisabled | Should -Be 0
    $op.States.WindowsDefault | Should -BeNullOrEmpty
    @(Get-RideSingleOperationPlan -Id $Id -Action Unset)[0].State | Should -Be 'WindowsDefault'
    $op.PendingAcceptance | Should -BeTrue
    $op.SupportedTargets.Count | Should -Be 0
    $op.Description | Should -Match 'not a general media-network block'
    (Get-RideProfile).Operations.Id | Should -Not -Contain $Id
    @(Get-RideCatalogValidationErrors (Get-RideCatalog)).Count | Should -Be 0
  }
  It 'blocks both candidates before any live policy inspection, including preview' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideCurrentState { throw 'blocked policy must not be inspected' }
      Mock Set-RideSettingState {}
      foreach ($id in @('windows.media-radio-preset-retrieval-policy', 'windows.media-drm-online-access-policy')) {
        $plan = @(Get-RideSingleOperationPlan -Id $id -Action Set -State Blocked)
        { Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false } | Should -Throw '*does not support*'
      }
      Should -Invoke Get-RideCurrentState -Times 0
      Should -Invoke Set-RideSettingState -Times 0
    }
  }
  It 'saves prior user-policy type and key presence before a failed write without elevation' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'media-user') } {
      param($Root)
      $script:MediaRoot = $Root
      $op = (Get-RideOperation windows.media-radio-preset-retrieval-policy).Clone()
      $op.SupportedTargets = @('Windows 11') # Fixture only; support remains empty.
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $false }
      Mock Get-RideStateRoot { $script:MediaRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:MediaRoot -Force | Out-Null; $script:MediaRoot }
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 'legacy custom'; ValueType = 'String'; KeyExisted = $true } }
      Mock Set-RideSettingState { throw 'fixture user policy write failed' }
      $plan = @([pscustomobject]@{ Operation = $op; State = 'Blocked' })
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*fixture user policy write failed*'
      $record = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter windows.media-radio-preset-retrieval-policy.json)[0]
      $snapshot = (Get-Content -LiteralPath $record.FullName -Raw | ConvertFrom-Json).Snapshot
      $snapshot.ValueType | Should -Be 'String'
      $snapshot.Value | Should -Be 'legacy custom'
      $snapshot.KeyExisted | Should -BeTrue
    }
  }
  It 'requires administrator for machine DRM writes after candidate acceptance' {
    InModuleScope RIDE.Engine {
      $op = (Get-RideOperation windows.media-drm-online-access-policy).Clone()
      $op.SupportedTargets = @('Windows 11') # Fixture only.
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $false }
      Mock Get-RideCurrentState { throw 'must not inspect rejected machine write' }
      { Invoke-RidePlan -Plan @([pscustomobject]@{ Operation = $op; State = 'Blocked' }) -Confirm:$false } | Should -Throw '*elevated*'
      Should -Invoke Get-RideCurrentState -Times 0
    }
  }
  It 'completes the explicit disabled policy without claiming blanket retirement' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.media-drm-online-access-policy -State pol"
    @([Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches.CompletionText) | Should -Be @('PolicyDisabled')
    $ops = (Get-RideCatalog).Operations | Where-Object ValueName -eq PreventMusicFileMetadataRetrieval
    $ops.Description | Should -Not -Match 'Retired radio presets'
    $ops.Description | Should -Match 'separate experimental candidates'
  }
}
