<#
.SYNOPSIS
  Verify the sixty-setting migration with isolated lifecycle and failure fixtures.
.DESCRIPTION
  Checks legacy provenance, discoverability, all named states, snapshots and exact
  restore. System handlers are mocked; TestDrive owns all state records. Exercises
  the real coordinated-value handler with mocked individual registry access.
.EXAMPLE
  Invoke-Pester .\tests\SixtySettings.Tests.ps1
.NOTES
  Compatibility: Pester 5.7.1 on Windows PowerShell 5.1 and PowerShell 7.
  Recovery: System APIs are mocked; no developer-machine integration tests.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-10: Cover sixty optional settings and coordinated recovery.
#>

BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogData.psm1') -Force
  $batchCases = @((Import-RideCatalogData -Path (Join-Path $PSScriptRoot '../catalog/operations.psd1')).Operations | Where-Object MigrationBatch -eq '2026-10-10-settings60' | ForEach-Object { @{ Id = $_.Id } })
}
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-RegistryValueSet.psm1') -Force
  $tokens = $null; $errors = $null
  $legacyAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../legacy/v2/lib-windows.psm1'), [ref]$tokens, [ref]$errors)
  $script:LegacyNames = @($legacyAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true).Name)
}

Describe 'Sixty-setting catalog and discovery' {
  It 'contains sixty new optional settings with no overlapping registry values' {
    $batch = @((Get-RideCatalog).Operations | Where-Object MigrationBatch -eq '2026-10-10-settings60')
    $batch.Count | Should -Be 60
    @($batch.Id | Select-Object -Unique).Count | Should -Be 60
    $profile = Get-RideProfile
    foreach ($operation in $batch) { $profile.Operations.Id | Should -Not -Contain $operation.Id }
    $locations = foreach ($operation in (Get-RideCatalog).Operations) {
      if ($operation.Kind -eq 'RegistryValue') { $operation.RegistryPath + '|' + $operation.ValueName }
      elseif ($operation.Kind -eq 'RegistryValueSet') { foreach ($member in $operation.RegistryValues) { $member.RegistryPath + '|' + $member.ValueName } }
    }
    @($locations | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
  }
  It 'reconciles <Id> with legacy names and declares usable states' -ForEach $batchCases {
    $operation = Get-RideOperation -Id $Id
    foreach ($selector in $operation.LegacySelectors) { $script:LegacyNames | Should -Contain $selector }
    $operation.DocumentationUri | Should -Match '^https://(learn|support)\.microsoft\.com/'
    $operation.SupportedTargets | Should -Be @('Windows 11')
    if ($operation.Kind -ne 'PowerSetting') { $operation.States.Keys | Should -Contain $operation.BaselineState }
    foreach ($state in $operation.States.Keys) {
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $state)
      $plan.Count | Should -Be 1
      $plan[0].State | Should -Be $state
    }
    if ($operation.Kind -eq 'RegistryValueSet') { @(Get-RideSingleOperationPlan -Id $Id -Action Unset)[0].State | Should -Be 'WindowsDefault' }
    { Get-RideSingleOperationPlan -Id $Id -Action Set -State Invalid } | Should -Throw
    (Show-RideCatalog -View settings).Id | Should -Contain $Id
  }
}

Describe 'Sixty-setting saved-run lifecycle' {
  BeforeEach {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) } {
      param($Root)
      $script:BatchRoot = $Root
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { Join-Path $script:BatchRoot $Scope }
      Mock Initialize-RideStateRoot { $path = Get-RideStateRoot -Scope $Scope; New-Item -ItemType Directory -Path $path -Force | Out-Null; $path }
      Mock Get-Item { [pscustomobject]@{ TestKey = $true } } -ParameterFilter { $LiteralPath -match '^HK(CU|LM):' }
      Mock Get-RideCurrentState { $script:BatchCurrent }
      Mock Set-RideSettingState { $script:BatchCurrent = [pscustomobject]@{ Exists = ($null -ne $Value); Value = $Value; ValueType = $Operation.ValueType } }
      Mock Set-RideRegistryValueSetState { $script:BatchCurrent = [pscustomobject]@{ Values = @($Operation.RegistryValues | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Exists = ($null -ne $Operation.States[$State][$_.Key]); Value = $Operation.States[$State][$_.Key]; ValueType = $_.ValueType; KeyExisted = $true } }) } }
      Mock Set-RideRegistryKeySetState { $script:BatchCurrent = [pscustomobject]@{ PresentCount = $(if ($State -eq 'Visible') { $Operation.RegistryPaths.Count } else { 0 }); TotalCount = $Operation.RegistryPaths.Count; Trees = @() } }
      Mock Set-RideWindowsServiceState {
        $desired = $Operation.States[$State]
        $script:BatchCurrent = [pscustomobject]@{
          StartupType = $desired.StartupType
          Status = $(if ($desired.ContainsKey('Status')) { $desired.Status } else { $script:BatchCurrent.Status })
          EffectiveDelayedAutoStart = $(if ($desired.ContainsKey('DelayedAutoStart')) { $desired.DelayedAutoStart } else { $script:BatchCurrent.EffectiveDelayedAutoStart })
        }
      }
      Mock Set-RidePowerSettingState { $script:BatchCurrent = [pscustomobject]@{ Available = $true; SchemeGuid = ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12); Index = $Operation.States[$State]; PowerIndex = $Operation.PowerIndex } }
      Mock Set-RideBootConfigurationState { $script:BatchCurrent = [pscustomobject]@{ Exists = ($null -ne $Operation.States[$State]); Value = $Operation.States[$State] } }
      Mock Restore-RideSettingState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RideRegistryValueSetState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RideRegistryKeySetState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RideWindowsServiceState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RidePowerSettingState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RideBootConfigurationState { $script:BatchCurrent = $script:BatchOriginal }
    }
  }
  It 'previews, captures, repeats all states and restores <Id>' -ForEach $batchCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id } {
      param($Id)
      $operation = Get-RideOperation -Id $Id
      $script:BatchCurrent = switch ($operation.Kind) {
        RegistryValue { [pscustomobject]@{ Exists = $true; Value = 'original custom'; ValueType = 'String' } }
        RegistryValueSet { [pscustomobject]@{ Values = @($operation.RegistryValues | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Exists = $true; Value = 'original custom'; ValueType = 'String'; KeyExisted = $true } }) } }
        RegistryKeySet { [pscustomobject]@{ PresentCount = 1; TotalCount = $operation.RegistryPaths.Count; Trees = @(@{ Path = $operation.RegistryPaths[0]; Exists = $true; Values = @(@{ Name = 'Original'; Value = 'keep' }) }) } }
        WindowsService { [pscustomobject]@{ StartupType = 'Manual'; Status = 'Stopped' } }
        PowerSetting { [pscustomobject]@{ Available = $true; SchemeGuid = ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12); Index = 99; PowerIndex = $operation.PowerIndex } }
        BootConfiguration { [pscustomobject]@{ Exists = $true; Value = 'DisplayAllFailures' } }
      }
      $script:BatchOriginal = $script:BatchCurrent
      $first = @($operation.States.Keys | Where-Object { -not (Test-RideCurrentStateMatch -Operation $operation -State $_ -CurrentState $script:BatchCurrent) })[0]
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $first)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path -LiteralPath $script:BatchRoot | Should -BeFalse
      $out = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $runId = ($out | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
      $runId | Should -Match '^[a-f0-9]{32}$'
      $saved = Get-Content -LiteralPath (Join-Path (Get-RideStateRoot -Scope $operation.Scope) "$runId/$Id.json") -Raw | ConvertFrom-Json
      $saved.OperationId | Should -Be $Id
      $saved.Scope | Should -Be $operation.Scope
      if ($operation.Kind -eq 'RegistryValueSet') { $saved.Snapshot.Values.Count | Should -Be $operation.RegistryValues.Count; $saved.Snapshot.Values[0].Value | Should -Be 'original custom' }
      foreach ($state in $operation.States.Keys) {
        $statePlan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $state)
        Invoke-RidePlan -Plan $statePlan -Confirm:$false | Out-Null
        Test-RideDesiredState -Operation $operation -State $state | Should -BeTrue
        @(Invoke-RidePlan -Plan $statePlan -Confirm:$false) | Should -Contain 'No changes were needed; no state record was created.'
      }
      $beforeRestore = $script:BatchCurrent | ConvertTo-Json -Depth 12 -Compress
      Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
      ($script:BatchCurrent | ConvertTo-Json -Depth 12 -Compress) | Should -Be $beforeRestore
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      ($script:BatchCurrent | ConvertTo-Json -Depth 12 -Compress) | Should -Be ($script:BatchOriginal | ConvertTo-Json -Depth 12 -Compress)
    }
  }
}

Describe 'Coordinated registry handler' {
  BeforeEach {
    $script:VectorOperation = Get-RideOperation -Id 'windows.control-panel-view'
  }
  It 'requires every component, its type and value, including unset components' {
    $state = [pscustomobject]@{ Values = @([pscustomobject]@{ Key = 'Page'; Exists = $true; Value = 1; ValueType = 'DWord' }, [pscustomobject]@{ Key = 'Icons'; Exists = $true; Value = 1; ValueType = 'DWord' }) }
    Test-RideRegistryValueSetMatch -Operation $script:VectorOperation -State SmallIcons -CurrentState $state | Should -BeTrue
    $state.Values[1].ValueType = 'String'
    Test-RideRegistryValueSetMatch -Operation $script:VectorOperation -State SmallIcons -CurrentState $state | Should -BeFalse
    $state.Values[1].Exists = $false
    Test-RideRegistryValueSetMatch -Operation $script:VectorOperation -State WindowsDefault -CurrentState $state | Should -BeFalse
    $state.Values[0].Exists = $false
    Test-RideRegistryValueSetMatch -Operation $script:VectorOperation -State WindowsDefault -CurrentState $state | Should -BeTrue
    $state.Values = @($state.Values[0])
    Test-RideRegistryValueSetMatch -Operation $script:VectorOperation -State WindowsDefault -CurrentState $state | Should -BeFalse
  }
  It 'propagates a later-component failure after the first write' {
    Mock Set-RideSettingState -ModuleName RIDE-RegistryValueSet { if ($Operation.Key -eq 'Icons') { throw 'second write failed' } }
    { Set-RideRegistryValueSetState -Operation $script:VectorOperation -State SmallIcons } | Should -Throw '*second write failed*'
    Should -Invoke Set-RideSettingState -ModuleName RIDE-RegistryValueSet -Times 1 -Exactly -ParameterFilter { $Operation.Key -eq 'Page' -and $Value -eq 1 }
  }
  It 'restores complete serialized snapshots in reverse order with prior types' {
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Operation = $script:VectorOperation } {
      param($Operation)
      $script:RestoreKeys = @()
      Mock Restore-RideSettingState { $script:RestoreKeys += $Operation.Key }
      $snapshot = @{ Values = @(@{ Key = 'Page'; Exists = $true; Value = 'custom'; ValueType = 'String'; KeyExisted = $true }, @{ Key = 'Icons'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $false }) } | ConvertTo-Json -Depth 8 | ConvertFrom-Json
      Restore-RideRegistryValueSetState -Operation $Operation -Snapshot $snapshot
      $script:RestoreKeys | Should -Be @('Icons', 'Page')
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.Key -eq 'Page' -and $Snapshot.ValueType -eq 'String' -and $Snapshot.Value -eq 'custom' }
    }
  }
  It 'rejects incomplete snapshots before any restore write' {
    Mock Restore-RideSettingState -ModuleName RIDE-RegistryValueSet {}
    { Restore-RideRegistryValueSetState -Operation $script:VectorOperation -Snapshot @{ Values = @(@{ Key = 'Page' }) } } | Should -Throw '*incomplete*'
    { Restore-RideRegistryValueSetState -Operation $script:VectorOperation -Snapshot @{ Values = @(@{ Key = 'Page' }, @{ Key = 'Page' }) } } | Should -Throw '*duplicate*'
    Should -Invoke Restore-RideSettingState -ModuleName RIDE-RegistryValueSet -Times 0 -Exactly
  }
  It 'preserves a full engine snapshot when a coordinated write fails' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'failed-vector') } {
      param($Root)
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { $Root }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $Root -Force | Out-Null; $Root }
      Mock Get-RideCurrentState { [pscustomobject]@{ Values = @([pscustomobject]@{ Key = 'Page'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $true }, [pscustomobject]@{ Key = 'Icons'; Exists = $true; Value = 'original'; ValueType = 'String'; KeyExisted = $true }) } }
      Mock Set-RideRegistryValueSetState { throw 'later component denied' }
      $plan = @(Get-RideSingleOperationPlan -Id windows.control-panel-view -Action Set -State SmallIcons)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*later component denied*'
      $saved = Get-ChildItem -LiteralPath $Root -Recurse -Filter windows.control-panel-view.json | Select-Object -First 1
      $record = Get-Content -LiteralPath $saved.FullName -Raw | ConvertFrom-Json
      $record.Snapshot.Values.Count | Should -Be 2
      $record.Snapshot.Values[0].Exists | Should -BeFalse
      $record.Snapshot.Values[1].ValueType | Should -Be 'String'
      $record.Snapshot.Values[1].Value | Should -Be 'original'
    }
  }
}

Describe 'Boot override recovery' {
  BeforeAll { Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-BootConfiguration.psm1') -Force }
  BeforeEach {
    Mock Invoke-RideBootConfigurationCommand -ModuleName RIDE-BootConfiguration {}
  }
  It 'does not delete an already absent override during set or restore' {
    Mock Get-RideBootConfigurationState -ModuleName RIDE-BootConfiguration { [pscustomobject]@{ Exists = $false; Value = $null } }
    $operation = Get-RideOperation -Id windows.boot-failure-recovery-policy
    Set-RideBootConfigurationState -Operation $operation -State WindowsDefault
    Restore-RideBootConfigurationState -Operation $operation -Snapshot @{ Exists = $false; Value = $null }
    Should -Invoke Invoke-RideBootConfigurationCommand -ModuleName RIDE-BootConfiguration -Times 0 -Exactly
  }
  It 'deletes an existing override when restoring captured absence' {
    Mock Get-RideBootConfigurationState -ModuleName RIDE-BootConfiguration { [pscustomobject]@{ Exists = $true; Value = 'IgnoreAllFailures' } }
    Restore-RideBootConfigurationState -Operation (Get-RideOperation -Id windows.boot-failure-recovery-policy) -Snapshot @{ Exists = $false; Value = $null }
    Should -Invoke Invoke-RideBootConfigurationCommand -ModuleName RIDE-BootConfiguration -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq '/deletevalue' -and $Arguments[2] -eq 'bootstatuspolicy' }
  }
  It 'preserves inspection errors rather than treating them as absence' {
    Mock Get-RideBootConfigurationState -ModuleName RIDE-BootConfiguration { throw 'BCD inspection denied' }
    { Restore-RideBootConfigurationState -Operation (Get-RideOperation -Id windows.boot-failure-recovery-policy) -Snapshot @{ Exists = $false } } | Should -Throw '*BCD inspection denied*'
    Should -Invoke Invoke-RideBootConfigurationCommand -ModuleName RIDE-BootConfiguration -Times 0 -Exactly
  }
}

Describe 'Service delayed-start preservation' {
  It 'captures and restores the original delayed-start value rather than the legacy override' {
    Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-Services.psm1') -Force
    InModuleScope RIDE-Services {
      $operation = @{ Id = 'test.search'; ServiceName = 'WSearch'; PreserveDelayedAutoStart = $true; States = @{ Enabled = @{ StartupType = 'Automatic'; Status = 'Running' } } }
      Mock Get-RideServiceDelayedAutoStart { $true }
      Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like 'HKLM:*' }
      Mock Get-Service { [pscustomobject]@{ Status = 'Stopped' } }
      Mock Get-CimInstance { [pscustomobject]@{ StartMode = 'Manual' } }
      Mock Get-RideSettingState { [pscustomobject]@{ KeyExisted = $true; Exists = $true; Value = 7; ValueType = 'DWord' } }
      Mock Restore-RideSettingState {}
      Mock Set-RideWindowsServiceConfiguration {}
      $before = Get-RideWindowsServiceState -Operation $operation
      $before.DelayedAutoStart.Value | Should -Be 7
      Set-RideWindowsServiceState -Operation $operation -State Enabled
      Restore-RideWindowsServiceState -Operation $operation -Snapshot $before
      Should -Invoke Set-RideWindowsServiceConfiguration -Times 1 -Exactly -ParameterFilter {
        $StartupType -eq 'Manual' -and $Status -eq 'Stopped' -and $Delayed -eq $true -and $DelayedSnapshot.Value -eq 7
      }
    }
  }
}
