<#
.SYNOPSIS
  Verify the remaining-setting migration with isolated lifecycle and failure fixtures.
.DESCRIPTION
  Checks legacy provenance, discoverability, all named states, snapshots and exact
  restore. System handlers are mocked; TestDrive owns all state records.
.EXAMPLE
  Invoke-Pester .\tests\RemainingSettings.Tests.ps1
.NOTES
  Compatibility: Pester 5.7.1 on Windows PowerShell 5.1 and PowerShell 7.
  Recovery: System APIs are mocked; no developer-machine integration tests.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-10: Cover remaining optional settings and coordinated recovery.
#>

BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogData.psm1') -Force
  $batchCases = @((Import-RideCatalogData -Path (Join-Path $PSScriptRoot '../catalog/operations.psd1')).Operations | Where-Object { $_.MigrationBatch -like '2026-10-10-remaining-settings-*' } | ForEach-Object { @{ Id = $_.Id } })
}
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-RegistryValueSet.psm1') -Force
  $tokens = $null; $errors = $null
  $legacyAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../legacy/v2/lib-windows.psm1'), [ref]$tokens, [ref]$errors)
  $script:LegacyNames = @($legacyAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true).Name)
}

Describe 'Remaining-setting catalog and discovery' {
  It 'contains remaining new optional settings with no overlapping registry values' {
    $batch = @((Get-RideCatalog).Operations | Where-Object { $_.MigrationBatch -like '2026-10-10-remaining-settings-*' })
    $batch.Count | Should -Be 36
    @($batch.Id | Select-Object -Unique).Count | Should -Be $batch.Count
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
    if ($operation.Kind -in @('RegistryValue', 'RegistryValueSet')) { $operation.States.Keys | Should -Contain $operation.BaselineState }
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

Describe 'Remaining-setting saved-run lifecycle' {
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
      Mock Set-RideWindowsServiceState { $script:BatchCurrent = [pscustomobject]@{ StartupType = $Operation.States[$State].StartupType; Status = $Operation.States[$State].Status } }
      Mock Set-RidePowerSettingState { $script:BatchCurrent = [pscustomobject]@{ Available = $true; SchemeGuid = ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12); Index = $Operation.States[$State]; PowerIndex = $Operation.PowerIndex } }
      Mock Set-RideBootConfigurationState { $script:BatchCurrent = [pscustomobject]@{ Exists = ($null -ne $Operation.States[$State]); Value = $Operation.States[$State] } }
      Mock Set-RideManagedSettingState {
        $value=$Operation.States[$State]
        $script:BatchCurrent = switch ($Operation.Kind) {
          ScheduledTask { [pscustomobject]@{ Available=$true; TaskPath=$Operation.TaskPath; TaskName=$Operation.TaskName; Enabled=$value } }
          AdapterBinding { [pscustomobject]@{ Available=$true; Bindings=@($Operation.ComponentIds | ForEach-Object { [pscustomobject]@{ InterfaceGuid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; Name='Adapter'; ComponentId=$_; Enabled=$value } }); RecoveryBindings=@() } }
          NetBios { [pscustomobject]@{SnapshotVersion=2;Available=$true;Entries=@([pscustomobject]@{Id='captured';Value=$value;Exists=$true;ValueType='DWord';KeyExisted=$true})} }
          RemoteDesktopFirewall { [pscustomobject]@{ Available=$true; Entries=@([pscustomobject]@{ Id='captured'; Value=$value }) } }
          PowerScheme { [pscustomobject]@{ Value=$value; AvailableSchemes=@($Operation.States.Values) } }
          SoundScheme { [pscustomobject]@{Available=$true;Selector=[pscustomobject]@{Exists=$true;KeyExisted=$true;Value=$value;ValueType='String'};Events=@([pscustomobject]@{Application='App';Event='Event';Current=[pscustomobject]@{Exists=$true;KeyExisted=$true;Value='';ValueType='String'};Presets=@{'.None'='';'.Default'=''}})} }
          default { [pscustomobject]@{ Value=$value } }
        }
      }
      Mock Restore-RideManagedSettingState { $script:BatchCurrent=$script:BatchOriginal }
      Mock Restore-RideSettingState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RideRegistryValueSetState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RideRegistryKeySetState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RideWindowsServiceState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RidePowerSettingState { $script:BatchCurrent = $script:BatchOriginal }
      Mock Restore-RideBootConfigurationState { $script:BatchCurrent = $script:BatchOriginal }
    }
  }
  It 'reports unavailable resources without creating an unrestorable saved run' {
    InModuleScope RIDE.Engine {
      $script:BatchCurrent=[pscustomobject]@{Available=$false;TaskPath='\Microsoft\Office\';TaskName='OfficeTelemetryAgentLogOn2016';Enabled=$null}
      $plan=@(Get-RideSingleOperationPlan -Id 'application.office-task-telemetry-logon-2016' -Action Set -State Disabled)
      {Invoke-RidePlan -Plan $plan -Confirm:$false} | Should -Throw '*unavailable*no state was saved*'
      Test-Path -LiteralPath $script:BatchRoot | Should -BeFalse
      Should -Invoke Set-RideManagedSettingState -Times 0
    }
  }
  It 'shows literal desired/live values and catalog state completion for native settings' {
    InModuleScope RIDE.Engine {
      $op=Get-RideOperation -Id 'windows.task-drive-optimization'
      $script:BatchCurrent=[pscustomobject]@{Available=$true;TaskPath=$op.TaskPath;TaskName=$op.TaskName;Enabled=$false}
      $status=@(Get-RideStatus -Profile @{SchemaVersion=1;Name='Fixture';Operations=@(@{Id=$op.Id;State='Enabled'})})[0]
      $status.DesiredValue | Should -Be 'True'
      $status.CurrentValue | Should -Be 'False'
      $status.CurrentValueType | Should -Be 'ScheduledTask'
      $status.InDesiredState | Should -BeFalse
      {Get-RideSingleOperationPlan -Id $op.Id -Action Unset} | Should -Throw '*explicit state*captured run*'
    }
  }
  It 'previews, captures, repeats all states and restores <Id>' -ForEach $batchCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id } {
      param($Id)
      $operation = Get-RideOperation -Id $Id
      $script:BatchCurrent = switch ($operation.Kind) {
        ScheduledTask { [pscustomobject]@{ Available=$true; TaskPath=$operation.TaskPath; TaskName=$operation.TaskName; Enabled=$false } }
        AdapterBinding { [pscustomobject]@{ Available=$true; Bindings=@($operation.ComponentIds | ForEach-Object { [pscustomobject]@{ InterfaceGuid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; Name='Adapter'; ComponentId=$_; Enabled=$true } }); RecoveryBindings=@() } }
        NetBios { [pscustomobject]@{SnapshotVersion=2;Available=$true;Entries=@([pscustomobject]@{Id='captured';Value='original';Exists=$true;ValueType='String';KeyExisted=$true})} }
        RemoteDesktopFirewall { [pscustomobject]@{ Available=$true; Entries=@([pscustomobject]@{ Id='captured'; Value='original' }) } }
        DefenderPreference { [pscustomobject]@{ Value=2 } }
        SoundScheme { [pscustomobject]@{Available=$true;Selector=[pscustomobject]@{Exists=$true;KeyExisted=$true;Value='custom';ValueType='String'};Events=@([pscustomobject]@{Application='App';Event='Event';Current=[pscustomobject]@{Exists=$true;KeyExisted=$true;Value='custom';ValueType='ExpandString'};Presets=@{'.None'='';'.Default'=''}})} }
        SmbProtocol { [pscustomobject]@{ Value=$true } }
        PowerScheme { [pscustomobject]@{ Value='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'; AvailableSchemes=@($operation.States.Values) } }
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
