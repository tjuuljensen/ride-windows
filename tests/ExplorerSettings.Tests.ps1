<#
.SYNOPSIS
  Verify the optional Explorer registry migration with isolated state fixtures.

.DESCRIPTION
  Checks legacy mappings, explicit and baseline states, planning, preview, repeat apply,
  saved snapshots, restoration dispatch, and recoverable failures. Registry reads and
  writes are mocked; saved runs use TestDrive. No Explorer process is restarted.

.EXAMPLE
  Invoke-Pester .\tests\ExplorerSettings.Tests.ps1

.INPUTS
  None. Pester supplies test case data.

.OUTPUTS
  Pester test results.

.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Repository catalog and engine modules.
  Recovery: TestDrive contains all generated state; system calls are mocked.
  Author: RIDE-Windows maintainers.
  Version: Repository test fixture; no independent CLI version.
  Changelog: 2026-10-09: Cover ten optional Explorer settings and saved-run recovery,
    including inverted visibility values for empty drives and folder merge prompts.
#>

BeforeDiscovery {
  $explorerCases = @(
    @{ Id = 'windows.empty-drives-visibility'; ValueName = 'HideDrivesWithNoMedia'; Key = 'Advanced'; On = 'Visible'; Off = 'Hidden'; OnValue = 0; OffValue = 1 }
    @{ Id = 'windows.folder-merge-conflicts'; ValueName = 'HideMergeConflicts'; Key = 'Advanced'; On = 'Shown'; Off = 'Hidden'; OnValue = 0; OffValue = 1 }
    @{ Id = 'windows.navigation-pane-all-folders'; ValueName = 'NavPaneShowAllFolders'; Key = 'Advanced'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0 }
    @{ Id = 'windows.explorer-title-full-path'; ValueName = 'FullPath'; Key = 'CabinetState'; On = 'Shown'; Off = 'Hidden'; OnValue = 1; OffValue = 0 }
    @{ Id = 'windows.protected-files-visibility'; ValueName = 'ShowSuperHidden'; Key = 'Advanced'; On = 'Visible'; Off = 'Hidden'; OnValue = 1; OffValue = 0 }
    @{ Id = 'windows.explorer-separate-process'; ValueName = 'SeparateProcess'; Key = 'Advanced'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0 }
    @{ Id = 'windows.restore-folder-windows'; ValueName = 'PersistBrowsers'; Key = 'Advanced'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0 }
    @{ Id = 'windows.sharing-wizard'; ValueName = 'SharingWizardOn'; Key = 'Advanced'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0 }
    @{ Id = 'windows.item-selection-checkboxes'; ValueName = 'AutoCheckSelect'; Key = 'Advanced'; On = 'Shown'; Off = 'Hidden'; OnValue = 1; OffValue = 0 }
    @{ Id = 'windows.thumbnail-display'; ValueName = 'IconsOnly'; Key = 'Advanced'; On = 'Enabled'; Off = 'Disabled'; OnValue = 0; OffValue = 1 }
  )
}

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  $script:DefaultProfile = Get-RideProfile -Path (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
}

Describe 'Optional Explorer registry metadata' {
  It 'maps <Id> to the legacy value and keeps the selection optional' -ForEach $explorerCases {
    $operation = Get-RideOperation -Id $Id
    $operation.RegistryPath | Should -Be "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\$Key"
    $operation.ValueName | Should -Be $ValueName
    $operation.ValueType | Should -Be 'DWord'
    $operation.Kind | Should -Be 'RegistryValue'
    $operation.Handler | Should -Be 'RegistryValue'
    $operation.Scope | Should -Be 'User'
    $operation.RequiresAdmin | Should -BeFalse
    $operation.Rollback | Should -Be 'Exact'
    $operation.SupportedTargets | Should -Be @('Windows 11')
    $operation.States[$On] | Should -Be $OnValue
    $operation.States[$Off] | Should -Be $OffValue
    $operation.States.ContainsKey('WindowsDefault') | Should -BeTrue
    $operation.States.WindowsDefault | Should -BeNullOrEmpty
    $operation.BaselineState | Should -Be 'WindowsDefault'
    $operation.DocumentationUri | Should -Match '^https://(learn|support)\.microsoft\.com/'
    @($script:DefaultProfile.Operations.Id) | Should -Not -Contain $Id
  }

  It 'distinguishes explicit zero, missing values and wrong types for <Id>' -ForEach $explorerCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id; On = $On; Off = $Off; OnValue = $OnValue; OffValue = $OffValue } {
      param($Id, $On, $Off, $OnValue, $OffValue)
      $operation = Get-RideOperation -Id $Id
      foreach ($selection in @(@{ State = $On; Value = $OnValue }, @{ State = $Off; Value = $OffValue })) {
        $current = [pscustomobject]@{ Exists = $true; Value = $selection.Value; ValueType = 'DWord' }
        Test-RideCurrentStateMatch -Operation $operation -State $selection.State -CurrentState $current | Should -BeTrue
        Get-RideCurrentStateName -Operation $operation -CurrentState $current | Should -Be $selection.State
        Test-RideCurrentStateMatch -Operation $operation -State WindowsDefault -CurrentState $current | Should -BeFalse
        $current.ValueType = 'String'
        Test-RideCurrentStateMatch -Operation $operation -State $selection.State -CurrentState $current | Should -BeFalse
      }
      $absent = [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null }
      Test-RideCurrentStateMatch -Operation $operation -State WindowsDefault -CurrentState $absent | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State $Off -CurrentState $absent | Should -BeFalse
      Get-RideCurrentStateName -Operation $operation -CurrentState $absent | Should -Be 'WindowsDefault'
      $unsetPlan = @(Get-RideSingleOperationPlan -Id $Id -Action Unset)
      $unsetPlan[0].State | Should -Be 'WindowsDefault'
    }
  }
}

Describe 'Optional Explorer saved-run lifecycle' {
  BeforeEach {
    InModuleScope RIDE.Engine -Parameters @{ StateRoot = (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) } {
      param($StateRoot)
      $script:ExplorerStateRoot = $StateRoot
      $script:ExplorerCurrent = [pscustomobject]@{ Exists = $true; Value = 'prior custom value'; ValueType = 'String' }
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $false }
      Mock Get-RideStateRoot { $script:ExplorerStateRoot }
      Mock Get-RideCurrentState { $script:ExplorerCurrent }
      Mock Get-Item { [pscustomobject]@{ MockRegistryKey = $true } } -ParameterFilter { $LiteralPath -like 'HKCU:*' }
      Mock Set-RideSettingState {
        $script:ExplorerCurrent = [pscustomobject]@{ Exists = ($null -ne $Value); Value = $Value; ValueType = $(if ($null -ne $Value) { $Operation.ValueType } else { $null }) }
      }
      Mock Restore-RideSettingState {
        $script:ExplorerCurrent = [pscustomobject]@{ Exists = $Snapshot.Exists; Value = $Snapshot.Value; ValueType = $Snapshot.ValueType }
      }
    }
  }

  It 'previews, saves, repeats and restores <Id> with its original type' -ForEach $explorerCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id; On = $On; OnValue = $OnValue } {
      param($Id, $On, $OnValue)
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $On)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path -LiteralPath $script:ExplorerStateRoot | Should -BeFalse
      Should -Invoke Set-RideSettingState -Times 0 -Exactly

      $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $runId = ($output | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
      $runId | Should -Match '^[a-f0-9]{32}$'
      $record = Get-Content -LiteralPath (Join-Path $script:ExplorerStateRoot "$runId/$Id.json") -Raw | ConvertFrom-Json
      $record.Scope | Should -Be 'User'
      $record.Snapshot.Exists | Should -BeTrue
      $record.Snapshot.KeyExisted | Should -BeTrue
      $record.Snapshot.Value | Should -Be 'prior custom value'
      $record.Snapshot.ValueType | Should -Be 'String'
      Test-RideDesiredState -Operation $plan[0].Operation -State $On | Should -BeTrue

      $repeat = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $repeat | Should -Contain 'No changes were needed; no state record was created.'
      Should -Invoke Set-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.Id -eq $Id -and $Value -eq $OnValue }
      @(Get-ChildItem -LiteralPath $script:ExplorerStateRoot -Directory).Count | Should -Be 1

      Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
      Should -Invoke Restore-RideSettingState -Times 0 -Exactly
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      $script:ExplorerCurrent.Value | Should -Be 'prior custom value'
      $script:ExplorerCurrent.ValueType | Should -Be 'String'
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.Id -eq $Id -and $Snapshot.ValueType -eq 'String' }
    }
  }

  It 'removes the override and retains an absent snapshot for <Id>' -ForEach $explorerCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id; On = $On } {
      param($Id, $On)
      $script:ExplorerCurrent = [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null }
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $On)
      $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $runId = ($output | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
      $record = Get-Content -LiteralPath (Join-Path $script:ExplorerStateRoot "$runId/$Id.json") -Raw | ConvertFrom-Json
      $record.Snapshot.Exists | Should -BeFalse

      $unset = @(Get-RideSingleOperationPlan -Id $Id -Action Unset)
      Invoke-RidePlan -Plan $unset -Confirm:$false | Out-Null
      Test-RideDesiredState -Operation $plan[0].Operation -State WindowsDefault | Should -BeTrue
      Should -Invoke Set-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.Id -eq $Id -and $null -eq $Value }
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      $script:ExplorerCurrent.Exists | Should -BeFalse
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly -ParameterFilter { -not $Snapshot.Exists }
    }
  }

  It 'preserves recoverable pre-change state when applying <Id> fails' -ForEach $explorerCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id; On = $On } {
      param($Id, $On)
      Mock Set-RideSettingState { throw 'simulated Explorer registry write failure' }
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $On)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*simulated Explorer registry write failure*'
      $records = @(Get-ChildItem -LiteralPath $script:ExplorerStateRoot -Recurse -Filter "$Id.json")
      $records.Count | Should -Be 1
      $record = Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json
      $record.Snapshot.Value | Should -Be 'prior custom value'
      $record.Snapshot.ValueType | Should -Be 'String'
      Restore-RideRun -RunId $record.RunId -Confirm:$false | Out-Null
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly
    }
  }
}
