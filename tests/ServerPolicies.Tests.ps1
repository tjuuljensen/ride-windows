<#
.SYNOPSIS
  Verify server policy metadata, explicit reverse semantics and application gates.
.DESCRIPTION
  Uses catalog data and mocked engine calls only. No logon, console, shutdown,
  registry write, package or disposable VM is invoked.
.EXAMPLE
  Invoke-Pester ./tests/ServerPolicies.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Add Server Manager and paired Shutdown Event Tracker checks.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
}
Describe 'Server Manager startup policy' {
  It 'keeps machine policy and console preference separate with distinct removal semantics' {
    $op = Get-RideOperation windows.server-manager-startup-policy
    $op.Scope | Should -Be 'Machine'
    $op.RequiresAdmin | Should -BeTrue
    $op.RegistryPath | Should -Be 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager'
    $op.ValueName | Should -Be 'DoNotOpenAtLogon'
    $op.States.Suppressed | Should -Be 1
    $op.States.AutomaticStartup | Should -Be 0
    $op.States.WindowsDefault | Should -BeNullOrEmpty
    @(Get-RideSingleOperationPlan -Id $op.Id -Action Unset)[0].State | Should -Be 'WindowsDefault'
    $op.Description | Should -Match 'console preference'
    $op.Description | Should -Match 'matching the legacy reverse'
    $op.CandidateTargets | Should -Be @('Windows Server 2025')
    (Get-RideProfile).Operations.Id | Should -Not -Contain $op.Id
    @(Get-RideCatalogValidationErrors (Get-RideCatalog)).Count | Should -Be 0
  }
  It 'blocks the server candidate before live inspection even in preview' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows Server 2025' }
      Mock Get-RideCurrentState { throw 'blocked server policy must not be inspected' }
      Mock Set-RideSettingState {}
      $op = Get-RideOperation windows.server-manager-startup-policy
      $op.SupportedTargets.Count | Should -Be 0
      $plan = @(Get-RideSingleOperationPlan -Id $op.Id -Action Set -State Suppressed)
      { Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false } | Should -Throw '*does not support*'
      Should -Invoke Get-RideCurrentState -Times 0
      Should -Invoke Set-RideSettingState -Times 0
    }
  }
  It 'completes explicit startup from the catalog' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.server-manager-startup-policy -State aut"
    @([Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches.CompletionText) | Should -Be @('AutomaticStartup')
  }
}

Describe 'Shutdown Event Tracker policy' {
  It 'coordinates <State> display choice and enablement without adding target support' -ForEach @(
    @{ State = 'Always'; Display = 1 },
    @{ State = 'WorkstationOnly'; Display = 2 },
    @{ State = 'ServerOnly'; Display = 3 }
  ) {
    $op = Get-RideOperation windows.shutdown-event-tracker-policy
    $op.States[$State].Enabled | Should -Be 1
    $op.States[$State].Display | Should -Be $Display
    $op.RegistryValues.ValueName | Should -Be @('ShutdownReasonUI', 'ShutdownReasonOn')
    $op.RequiresAdmin | Should -BeTrue
    $op.CandidateTargets | Should -Be @('Windows Server 2025')
    $op.SupportedTargets.Count | Should -Be 0
    (Get-RideProfile).Operations.Id | Should -Not -Contain $op.Id
  }
  It 'disables only enablement and matches while preserving custom display type/data' {
    $op = Get-RideOperation windows.shutdown-event-tracker-policy
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Op = $op } {
      param($Op)
      $script:TrackerWrites = @()
      Mock Set-RideSettingState { $script:TrackerWrites += [pscustomobject]@{ Key = $Operation.Key; Value = $Value } }
      $current = [pscustomobject]@{ Values = @(
        @{ Key = 'Display'; Exists = $true; Value = 'custom legacy display'; ValueType = 'String'; KeyExisted = $true },
        @{ Key = 'Enabled'; Exists = $true; Value = 0; ValueType = 'DWord'; KeyExisted = $true }
      ) }
      Test-RideRegistryValueSetMatch $Op Disabled $current | Should -BeTrue
      Set-RideRegistryValueSetState $Op Disabled
      $script:TrackerWrites.Count | Should -Be 1
      $script:TrackerWrites[0].Key | Should -Be 'Enabled'
      $script:TrackerWrites[0].Value | Should -Be 0
      Should -Invoke Set-RideSettingState -Times 0 -ParameterFilter { $Operation.Key -eq 'Display' }
      $current.Values = @($current.Values | Where-Object Key -ne Display)
      Test-RideRegistryValueSetMatch $Op Disabled $current | Should -BeFalse
    }
  }
  It 'writes enabled display selection before the enabling gate' {
    $op = Get-RideOperation windows.shutdown-event-tracker-policy
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Op = $op } {
      param($Op)
      $script:TrackerWrites = @()
      Mock Set-RideSettingState { $script:TrackerWrites += ($Operation.Key + ':' + $Value) }
      Set-RideRegistryValueSetState $Op ServerOnly
      $script:TrackerWrites | Should -Be @('Display:3', 'Enabled:1')
    }
  }
  It 'removes both explicit overrides while documenting the narrower legacy reverse' {
    $op = Get-RideOperation windows.shutdown-event-tracker-policy
    @(Get-RideSingleOperationPlan -Id $op.Id -Action Unset)[0].State | Should -Be 'WindowsDefault'
    $op.Description | Should -Match 'legacy enable selector removed only enablement'
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Op = $op } {
      param($Op)
      Mock Set-RideSettingState {}
      Set-RideRegistryValueSetState $Op WindowsDefault
      Should -Invoke Set-RideSettingState -Times 2 -Exactly -ParameterFilter { $null -eq $Value }
    }
  }
  It 'restores the actual typed pair in reverse order including an absent gate' {
    $op = Get-RideOperation windows.shutdown-event-tracker-policy
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Op = $op } {
      param($Op)
      $script:TrackerRestores = @()
      Mock Restore-RideSettingState { $script:TrackerRestores += $Operation.Key }
      $snapshot = @{ Values = @(
        @{ Key = 'Display'; Exists = $true; Value = 'custom'; ValueType = 'String'; KeyExisted = $true },
        @{ Key = 'Enabled'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $true }
      ) } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
      Restore-RideRegistryValueSetState $Op $snapshot
      $script:TrackerRestores | Should -Be @('Enabled', 'Display')
      Should -Invoke Restore-RideSettingState -Times 1 -ParameterFilter { $Operation.Key -eq 'Display' -and $Snapshot.ValueType -eq 'String' -and $Snapshot.Value -eq 'custom' }
      Should -Invoke Restore-RideSettingState -Times 1 -ParameterFilter { $Operation.Key -eq 'Enabled' -and -not $Snapshot.Exists }
    }
  }
  It 'rejects invalid <Problem> marker before any component write' -ForEach @(
    @{ Problem = 'false'; Marker = @{ KeepCurrent = $false } },
    @{ Problem = 'string'; Marker = @{ KeepCurrent = 'true' } },
    @{ Problem = 'extra field'; Marker = @{ KeepCurrent = $true; Other = 1 } }
  ) {
    $catalog = Get-RideCatalog
    $op = $catalog.Operations | Where-Object Id -eq windows.shutdown-event-tracker-policy
    $op.States.Always.Enabled = $Marker # Later component must still fail before first write.
    @(Get-RideCatalogValidationErrors $catalog).Count | Should -BeGreaterThan 0
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Op = $op } {
      param($Op)
      Mock Set-RideSettingState {}
      { Set-RideRegistryValueSetState $Op Always } | Should -Throw '*KeepCurrent marker is invalid*'
      Should -Invoke Set-RideSettingState -Times 0
    }
  }
  It 'blocks candidate application before inspecting shutdown policy' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows Server 2025' }
      Mock Get-RideCurrentState { throw 'blocked policy must not be inspected' }
      Mock Set-RideRegistryValueSetState {}
      $op = Get-RideOperation windows.shutdown-event-tracker-policy
      { Invoke-RidePlan -Plan @([pscustomobject]@{ Operation = $op; State = 'Disabled' }) -WhatIf -Confirm:$false } | Should -Throw '*does not support*'
      Should -Invoke Get-RideCurrentState -Times 0
      Should -Invoke Set-RideRegistryValueSetState -Times 0
    }
  }
  It 'captures both old values and types before a partial enabled-policy write fails' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'tracker-state') } {
      param($Root)
      $script:TrackerRoot = $Root
      $op = (Get-RideOperation windows.shutdown-event-tracker-policy).Clone()
      $op.SupportedTargets = @('Windows Server 2025') # Fixture only.
      Mock Get-RidePlatform { 'Windows Server 2025' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { $script:TrackerRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:TrackerRoot -Force | Out-Null; $script:TrackerRoot }
      Mock Get-RideCurrentState { [pscustomobject]@{ Values = @(
        @{ Key = 'Display'; Exists = $true; Value = 'custom'; ValueType = 'String'; KeyExisted = $true },
        @{ Key = 'Enabled'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $true }
      ) } }
      Mock Set-RideRegistryValueSetState {
        $file = @(Get-ChildItem -LiteralPath $script:TrackerRoot -Recurse -Filter windows.shutdown-event-tracker-policy.json)[0]
        $saved = (Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json).Snapshot
        if ($saved.Values.Count -ne 2 -or $saved.Values[0].ValueType -ne 'String') { throw 'pair capture missing' }
        throw 'fixture partial tracker write failure'
      }
      $plan = @([pscustomobject]@{ Operation = $op; State = 'Always' })
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*fixture partial tracker write failure*'
    }
  }
  It 'completes both scope choices and renders preserved data explicitly' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.shutdown-event-tracker-policy -State w"
    @([Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches.CompletionText | Sort-Object) | Should -Be @('WindowsDefault', 'WorkstationOnly')
    InModuleScope RIDE.Engine {
      $op = Get-RideOperation windows.shutdown-event-tracker-policy
      ConvertTo-RideDisplayValue $op.States.Disabled | Should -Be 'Display: <keep current>; Enabled: 0'
    }
  }
}
