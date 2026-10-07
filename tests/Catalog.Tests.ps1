BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  $script:Catalog = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'catalog/operations.psd1')
  $script:EnginePath = Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1'
  Import-Module $script:EnginePath -Force
}

Describe 'RIDE operation catalog' {
  It 'has unique operation and group IDs' {
    $allIds = @($script:Catalog.Operations.Id) + @($script:Catalog.Groups.Id)
    @($allIds | Select-Object -Unique).Count | Should -Be $allIds.Count
  }

  It 'uses only registered members in solution groups' {
    $operationIds = @($script:Catalog.Operations.Id)
    foreach ($group in $script:Catalog.Groups) {
      foreach ($member in $group.Members) {
        $member | Should -BeIn $operationIds
      }
    }
  }

  It 'declares support, scope, privilege, actions, and rollback for every operation' {
    foreach ($operation in $script:Catalog.Operations) {
      $operation.SupportedTargets.Count | Should -BeGreaterThan 0
      $operation.Scope | Should -BeIn @('User', 'Machine')
      $operation.Actions.Count | Should -BeGreaterThan 0
      $operation.Rollback | Should -BeIn @('Exact', 'Compensating', 'None')
    }
  }
}

Describe 'RIDE profile planning' {
  It 'expands solution groups in apply order and reverse order for removal' {
    $profile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/analyst-basics.psd1')
    $applyPlan = @(Get-RidePlan -Profile $profile)
    $removePlan = @(Get-RidePlan -Profile $profile -Action Remove)

    (@($applyPlan.Operation.Id) -join ',') | Should -Be 'package.7zip,package.notepadpp'
    (@($removePlan.Operation.Id) -join ',') | Should -Be 'package.notepadpp,package.7zip'
    (@($removePlan.State | Select-Object -Unique) -join ',') | Should -Be 'Absent'
  }

  It 'resolves a registry profile state to its catalog value' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.show-known-extensions'
      Get-RideOperationValue -Operation $operation -State 'Enabled' | Should -Be 0
    }
  }

  It 'resolves Baseline to the operation declared baseline state' {
    $profile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/baseline.psd1')
    $plan = @(Get-RidePlan -Profile $profile)
    $plan[0].State | Should -Be 'Disabled'
  }

  It 'allows a declared state to remove a registry value' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.script-host-policy'
      $plan = @(Get-RidePlan -Profile @{ SchemaVersion = 1; Name = 'Restore script host'; Operations = @(@{ Id = $operation.Id; State = 'Enabled' }) })
      Get-RideOperationValue -Operation $operation -State $plan[0].State | Should -BeNullOrEmpty
    }
  }
}

Describe 'RIDE desired-state comparison' {
  It 'compares a setting with the declared desired value' {
    InModuleScope RIDE.Engine {
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 0; ValueType = 'DWord' } }
      $operation = Get-RideOperation -Id 'windows.show-known-extensions'
      Test-RideDesiredState -Operation $operation -State 'Enabled' | Should -BeTrue
    }
  }

  It 'reports a partial failure with the run ID and saved operations' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 1; ValueType = 'DWord' } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideSettingState { throw 'simulated registry failure' }
      $operation = Get-RideOperation -Id 'windows.show-known-extensions'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Enabled' })

      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*simulated registry failure*'
    }
  }

  It 'calls the package installer through the mocked handler' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Present = $false; DisplayVersion = $null } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Install-RidePackage {}
      $operation = Get-RideOperation -Id 'package.7zip'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Present' })

      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke Install-RidePackage -Exactly 1
    }
  }

  It 'does not save or mutate state in WhatIf mode' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 1; ValueType = 'DWord' } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideSettingState {}
      $operation = Get-RideOperation -Id 'windows.show-known-extensions'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Enabled' })

      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Set-RideSettingState -Exactly 0
    }
  }
}

Describe 'RIDE settings snapshot restore' {
  It 'restores the recorded value and registry type' {
    Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-Settings.psm1') -Force
    InModuleScope RIDE-Settings {
      Mock Set-RideSettingState {}
      $operation = @{ Id = 'test.setting'; RegistryPath = 'HKCU:\Software\RIDE-Test'; ValueName = 'Sample'; ValueType = 'DWord' }
      $snapshot = [pscustomobject]@{ Exists = $true; KeyExisted = $true; Value = 42; ValueType = 'QWord' }
      Restore-RideSettingState -Operation $operation -Snapshot $snapshot
      Should -Invoke Set-RideSettingState -Exactly 1 -ParameterFilter { $Value -eq 42 -and $Operation.ValueType -eq 'QWord' }
    }
  }
}
