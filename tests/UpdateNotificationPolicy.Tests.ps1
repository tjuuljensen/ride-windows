<#
.SYNOPSIS
  Verify coordinated Windows Update notification candidates without changing Windows.
.DESCRIPTION
  Uses catalog data, mocked registry access and TestDrive saved records. No update
  scan, installation, reboot, live policy, VM or publisher API is invoked.
.EXAMPLE
  Invoke-Pester ./tests/UpdateNotificationPolicy.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Cover gate/level/checkbox, observations and pending/build gates.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
}

Describe 'Windows Update notification policy' {
  It 'separates the gate from the level, explicit default, disabled policy and override removal' {
    $op = Get-RideOperation windows.update-notification-display-policy
    $op.PendingAcceptance | Should -BeTrue
    $op.SupportedTargets.Count | Should -Be 0
    $op.MinimumBuild | Should -Be 22621
    $op.States.DefaultNotifications.Gate | Should -Be 1
    $op.States.DefaultNotifications.Level | Should -Be 0
    $op.States.HideIncludingRestartWarnings.Gate | Should -Be 1
    $op.States.HideIncludingRestartWarnings.Level | Should -Be 2
    $op.States.KeepRestartWarningsDuringActiveHours.Level | Should -Be 1
    $op.States.KeepRestartWarningsDuringActiveHours.DuringActiveHours | Should -Be 1
    $op.States.PolicyDisabled.Gate | Should -Be 0
    $op.States.PolicyDisabled.Level | Should -BeNullOrEmpty
    @($op.States.WindowsDefault.Values | Where-Object { $null -ne $_ }).Count | Should -Be 0
    (Get-RideProfile).Operations.Id | Should -Not -Contain $op.Id
    @(Get-RideCatalogValidationErrors (Get-RideCatalog)).Count | Should -Be 0
  }
  It 'writes only the complete declared payload and never the observation for <State>' -ForEach @(
    @{ State = 'DefaultNotifications' }, @{ State = 'KeepRestartWarnings' },
    @{ State = 'KeepRestartWarningsDuringActiveHours' }, @{ State = 'HideIncludingRestartWarnings' },
    @{ State = 'HideIncludingRestartWarningsDuringActiveHours' }, @{ State = 'PolicyDisabled' }, @{ State = 'WindowsDefault' }
  ) {
    $op = Get-RideOperation windows.update-notification-display-policy
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Operation = $op; State = $State } {
      param($Operation, $State)
      $script:NotificationDesired = $Operation.States[$State]
      Mock Set-RideSettingState {}
      Set-RideRegistryValueSetState $Operation $State
      Should -Invoke Set-RideSettingState -Times 3 -Exactly
      Should -Invoke Set-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.ValueName -eq 'SetUpdateNotificationLevel' -and $Value -eq $script:NotificationDesired.Gate }
      Should -Invoke Set-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.ValueName -eq 'UpdateNotificationLevel' -and $Value -eq $script:NotificationDesired.Level }
      Should -Invoke Set-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.ValueName -eq 'NoUpdateNotificationsDuringActiveHours' -and $Value -eq $script:NotificationDesired.DuringActiveHours }
      Should -Invoke Set-RideSettingState -Times 0 -ParameterFilter { $Operation.ValueName -eq 'Debugger' -or $Operation.Key -eq 'LegacyDebugger' }
    }
  }
  It 'reads and reports legacy interception separately from the three recoverable values' {
    $op = Get-RideOperation windows.update-notification-display-policy
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Operation = $op } {
      param($Operation)
      Mock Get-RideSettingState { [pscustomobject]@{ Exists = $true; ValueType = 'String'; Value = $(if ($Operation.Key -eq 'LegacyDebugger') { 'cmd.exe' } else { 'fixture' }) } }
      Mock Get-Item { [pscustomobject]@{ KeyExists = $true } }
      Mock Set-RideSettingState {}
      $current = Get-RideRegistryValueSetState $Operation
      $current.Values.Count | Should -Be 3
      $current.ReadOnlyObservations.Count | Should -Be 1
      $current.ReadOnlyObservations[0].Key | Should -Be 'LegacyDebugger'
      $current.ReadOnlyObservations[0].Value | Should -Be 'cmd.exe'
      Should -Invoke Set-RideSettingState -Times 0
    }
    InModuleScope RIDE.Engine {
      $op = Get-RideOperation windows.update-notification-display-policy
      $current = [pscustomobject]@{ Values = @(); ReadOnlyObservations = @(@{ Key = 'LegacyDebugger'; Exists = $true; Value = 'cmd.exe'; ValueType = 'String' }) }
      Get-RideCurrentValueText $op $current | Should -Match 'Read-only observations: LegacyDebugger: cmd.exe'
    }
  }
  It 'restores mixed typed/absent policy values in reverse order without restoring observed debugger data' {
    $op = Get-RideOperation windows.update-notification-display-policy
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Operation = $op } {
      param($Operation)
      $script:NotificationRestoreKeys = @()
      Mock Restore-RideSettingState { $script:NotificationRestoreKeys += $Operation.Key }
      $snapshot = @{ Values = @(
        @{ Key = 'Gate'; Exists = $true; Value = 0; ValueType = 'DWord'; KeyExisted = $true },
        @{ Key = 'Level'; Exists = $true; Value = 'custom'; ValueType = 'String'; KeyExisted = $true },
        @{ Key = 'DuringActiveHours'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $true }
      ); ReadOnlyObservations = @(@{ Key = 'LegacyDebugger'; Exists = $true; Value = 'cmd.exe' }) } | ConvertTo-Json -Depth 6 | ConvertFrom-Json
      Restore-RideRegistryValueSetState $Operation $snapshot
      $script:NotificationRestoreKeys | Should -Be @('DuringActiveHours', 'Level', 'Gate')
      Should -Invoke Restore-RideSettingState -Times 1 -ParameterFilter { $Operation.Key -eq 'Level' -and $Snapshot.ValueType -eq 'String' -and $Snapshot.Value -eq 'custom' }
      Should -Invoke Restore-RideSettingState -Times 0 -ParameterFilter { $Operation.Key -eq 'LegacyDebugger' }
    }
  }
  It 'keeps candidate and minimum-build guards ahead of live policy inspection or writes' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideCurrentState { throw 'must not inspect blocked candidate/build' }
      Mock Set-RideRegistryValueSetState {}
      $op = Get-RideOperation windows.update-notification-display-policy
      $plan = @([pscustomobject]@{ Operation = $op; State = 'DefaultNotifications' })
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*does not support*'
      $fixture = $op.Clone(); $fixture.SupportedTargets = @('Windows 11')
      $fixturePlan = @([pscustomobject]@{ Operation = $fixture; State = 'DefaultNotifications' })
      Mock Get-ItemProperty { [pscustomobject]@{ CurrentBuildNumber = 22620 } }
      { Invoke-RidePlan -Plan $fixturePlan -Confirm:$false } | Should -Throw '*requires Windows build 22621*'
      Should -Invoke Get-RideCurrentState -Times 0
      Should -Invoke Set-RideRegistryValueSetState -Times 0
    }
  }
  It 'captures all policy components before partial failure and excludes observations from saved recovery' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'notification-state') } {
      param($Root)
      $script:NotificationRoot = $Root
      $op = (Get-RideOperation windows.update-notification-display-policy).Clone()
      $op.SupportedTargets = @('Windows 11')
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-ItemProperty { [pscustomobject]@{ CurrentBuildNumber = 22621 } }
      Mock Get-RideStateRoot { $script:NotificationRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:NotificationRoot -Force | Out-Null; $script:NotificationRoot }
      Mock Get-RideCurrentState {
        [pscustomobject]@{ Values = @(
          @{ Key = 'Gate'; Exists = $true; Value = 0; ValueType = 'DWord'; KeyExisted = $true },
          @{ Key = 'Level'; Exists = $true; Value = 'custom'; ValueType = 'String'; KeyExisted = $true },
          @{ Key = 'DuringActiveHours'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $true }
        ); ReadOnlyObservations = @(@{ Key = 'LegacyDebugger'; Value = 'cmd.exe' }) }
      }
      Mock Set-RideRegistryValueSetState { throw 'fixture later policy component failure' }
      $plan = @([pscustomobject]@{ Operation = $op; State = 'KeepRestartWarnings' })
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*fixture later policy component failure*'
      $records = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter windows.update-notification-display-policy.json)
      $snapshot = (Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json).Snapshot
      $snapshot.Values.Count | Should -Be 3
      $snapshot.Values[1].ValueType | Should -Be 'String'
      $snapshot.PSObject.Properties.Name | Should -Not -Contain 'ReadOnlyObservations'
    }
  }
  It 'completes named states from the catalog' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.update-notification-display-policy -State keep"
    $matches = [Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches
    @($matches.CompletionText | Sort-Object) | Should -Be @('KeepRestartWarnings', 'KeepRestartWarningsDuringActiveHours')
  }
  It 'rejects <Problem> inspection/build metadata through shared validation' -ForEach @(
    @{ Problem = 'wrong observation scope'; Mode = 'Scope' },
    @{ Problem = 'observation of a writable value'; Mode = 'Overlap' },
    @{ Problem = 'unbounded observations'; Mode = 'Count' },
    @{ Problem = 'invalid minimum build'; Mode = 'Build' }
  ) {
    $catalog = Get-RideCatalog
    $op = $catalog.Operations | Where-Object Id -eq windows.update-notification-display-policy
    switch ($Mode) {
      Scope { $op.ReadOnlyRegistryValues[0].RegistryPath = 'HKCU:\Software\Example' }
      Overlap { $op.ReadOnlyRegistryValues[0].RegistryPath = $op.RegistryValues[0].RegistryPath; $op.ReadOnlyRegistryValues[0].ValueName = $op.RegistryValues[0].ValueName }
      Count { $op.ReadOnlyRegistryValues = @(1..6 | ForEach-Object { @{ Key = "Observe$_"; RegistryPath = 'HKLM:\Software\Example'; ValueName = "Value$_"; ValueType = 'String' } }) }
      Build { $op.MinimumBuild = 0 }
    }
    @(Get-RideCatalogValidationErrors $catalog).Count | Should -BeGreaterThan 0
  }
}
