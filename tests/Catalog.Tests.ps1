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

  It 'provides authoritative documentation references for settings and product references for packages' {
    foreach ($operation in $script:Catalog.Operations) {
      if ($operation.Kind -eq 'RegistryValue') {
        $operation.DocumentationUri | Should -Match '^https://(learn|support)\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'WindowsService') {
        $operation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'BackgroundAppOverrides') {
        $operation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'BootConfiguration') {
        $operation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'Package') {
        $operation.ProductUri | Should -Match '^https://'
      }
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

  It 'maps the legacy inking and typing setting to Disabled and restores its baseline by unsetting it' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      Get-RideOperationValue -Operation $operation -State 'Disabled' | Should -Be 0
      Get-RideOperationValue -Operation $operation -State 'Enabled' | Should -BeNullOrEmpty
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $defaultPlan = @(Get-RidePlan -Profile $defaultProfile)
    ($defaultPlan | Where-Object { $_.Operation.Id -eq 'windows.inking-typing-data' }).State | Should -Be 'Disabled'

    $baselinePlan = @(Get-RidePlan -Profile @{ SchemaVersion = 1; Name = 'Inking and typing baseline'; Operations = @(@{ Id = 'windows.inking-typing-data'; State = 'Baseline' }) })
    $baselinePlan[0].State | Should -Be 'Enabled'
  }

  It 'allows a declared state to remove a registry value' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.script-host-policy'
      $plan = @(Get-RidePlan -Profile @{ SchemaVersion = 1; Name = 'Restore script host'; Operations = @(@{ Id = $operation.Id; State = 'Enabled' }) })
      Get-RideOperationValue -Operation $operation -State $plan[0].State | Should -BeNullOrEmpty
    }
  }

  It 'maps the low-risk network selectors to reversible registry states in the default profile' {
    InModuleScope RIDE.Engine {
      $proxy = Get-RideOperation -Id 'windows.proxy-autoconfig-url'
      Get-RideOperationValue -Operation $proxy -State 'Disabled' | Should -Be ''
      Get-RideOperationValue -Operation $proxy -State 'Enabled' | Should -BeNullOrEmpty
      $llmnr = Get-RideOperation -Id 'windows.llmnr-policy'
      Get-RideOperationValue -Operation $llmnr -State 'Disabled' | Should -Be 0
      Get-RideOperationValue -Operation $llmnr -State 'Enabled' | Should -BeNullOrEmpty
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    ($defaultProfile.Operations | Where-Object { $_.Id -in @('windows.proxy-autoconfig-url', 'windows.llmnr-policy') } | ForEach-Object State | Select-Object -Unique) | Should -Be 'Disabled'
  }

  It 'maps low-risk privacy policy values to Disabled and restores their enabled baseline by unsetting' {
    $ids = @(
      'windows.tailored-experiences-policy',
      'windows.activity-history-feed-policy',
      'windows.activity-history-publish-policy',
      'windows.activity-history-upload-policy',
      'windows.location-service-policy',
      'windows.location-scripting-policy',
      'windows.advertising-id-policy',
      'windows.website-language-list-policy'
    )
    foreach ($id in $ids) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $id | Select-Object -First 1
      $operation.States.Disabled | Should -Not -BeNullOrEmpty
      $operation.States.Enabled | Should -BeNullOrEmpty
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    ($defaultProfile.Operations | Where-Object { $_.Id -in $ids }).Count | Should -Be $ids.Count
  }

  It 'maps low-risk service-family registry settings to their declared states' {
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $plan = @(Get-RidePlan -Profile $defaultProfile)
    ($plan | Where-Object { $_.Operation.Id -in @('windows.maintenance-wake-policy', 'windows.maintenance-wake-timer', 'windows.shared-experiences-policy') } | ForEach-Object State | Select-Object -Unique) | Should -Be 'Disabled'
    ($plan | Where-Object { $_.Operation.Id -eq 'windows.long-paths-policy' }).State | Should -Be 'Enabled'

    $longPaths = $script:Catalog.Operations | Where-Object Id -eq 'windows.long-paths-policy'
    $longPaths.States.Enabled | Should -Be 1
    $longPaths.States.Disabled | Should -Be 0
  }

  It 'maps the first UI Tweaks batch to reversible registry states in the default profile' {
    $expected = @{
      'windows.action-center-policy' = @{ State = 'Disabled'; Value = 1 }
      'windows.toast-notifications-policy' = @{ State = 'Disabled'; Value = 0 }
      'windows.lock-screen-blur' = @{ State = 'Disabled'; Value = 1 }
      'windows.sticky-keys-prompts' = @{ State = 'Disabled'; Value = '506' }
      'windows.toggle-keys-prompts' = @{ State = 'Disabled'; Value = '58' }
      'windows.filter-keys-prompts' = @{ State = 'Disabled'; Value = '122' }
      'windows.file-operation-details' = @{ State = 'Enabled'; Value = 1 }
      'windows.taskbar-search-visibility' = @{ State = 'Hidden'; Value = 0 }
      'windows.task-view-button' = @{ State = 'Hidden'; Value = 0 }
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $planned = @(Get-RidePlan -Profile $defaultProfile)
    foreach ($id in $expected.Keys) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $id | Select-Object -First 1
      $operation | Should -Not -BeNullOrEmpty
      $desired = $expected[$id]
      $plannedOperation = $planned | Where-Object { $_.Operation.Id -eq $id } | Select-Object -First 1
      $plannedOperation.State | Should -Be $desired.State
      InModuleScope RIDE.Engine -Parameters @{ Id = $id; State = $desired.State; Value = $desired.Value } {
        param($Id, $State, $Value)
        $operation = Get-RideOperation -Id $Id
        Get-RideOperationValue -Operation $operation -State $State | Should -Be $Value
      }
    }
  }

  It 'maps the second UI Tweaks batch to reversible registry states in the default profile' {
    $expected = @{
      'windows.taskbar-combine-primary' = @{ State = 'WhenFull'; Value = 1 }
      'windows.taskbar-combine-secondary' = @{ State = 'WhenFull'; Value = 1 }
      'windows.taskbar-people-icon' = @{ State = 'Hidden'; Value = 0 }
      'windows.tray-icon-promotion' = @{ State = 'ShowAll'; Value = 1 }
      'windows.store-app-suggestion' = @{ State = 'Disabled'; Value = 1 }
      'windows.new-app-alert' = @{ State = 'Disabled'; Value = 1 }
      'windows.startup-sound' = @{ State = 'Disabled'; Value = 1 }
      'windows.taskbar-widgets' = @{ State = 'Hidden'; Value = 0 }
      'windows.taskbar-chat' = @{ State = 'Hidden'; Value = 0 }
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $planned = @(Get-RidePlan -Profile $defaultProfile)
    foreach ($id in $expected.Keys) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $id | Select-Object -First 1
      $operation | Should -Not -BeNullOrEmpty
      $desired = $expected[$id]
      $plannedOperation = $planned | Where-Object { $_.Operation.Id -eq $id } | Select-Object -First 1
      $plannedOperation.State | Should -Be $desired.State
      InModuleScope RIDE.Engine -Parameters @{ Id = $id; State = $desired.State; Value = $desired.Value } {
        param($Id, $State, $Value)
        $operation = Get-RideOperation -Id $Id
        Get-RideOperationValue -Operation $operation -State $State | Should -Be $Value
      }
    }
  }

  It 'maps Edge Alt+Tab tab exclusion to the declared scalar value' {
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $planned = @(Get-RidePlan -Profile $defaultProfile | Where-Object { $_.Operation.Id -eq 'windows.edge-tabs-alt-tab' })
    $planned.Count | Should -Be 1
    $planned[0].State | Should -Be 'Excluded'

    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.edge-tabs-alt-tab'
      Get-RideOperationValue -Operation $operation -State 'Excluded' | Should -Be 3
      Get-RideOperationValue -Operation $operation -State 'RecentTabs' | Should -Be 1
    }
  }

  It 'maps low-risk Explorer UI selectors to reversible registry states in the default profile' {
    $expected = @{
      'windows.hidden-files-visibility' = @{ State = 'Visible'; Value = 1 }
      'windows.navigation-pane-auto-expand' = @{ State = 'Enabled'; Value = 1 }
      'windows.sync-provider-notifications' = @{ State = 'Hidden'; Value = 0 }
      'windows.explorer-recent-shortcuts' = @{ State = 'Hidden'; Value = 0 }
      'windows.explorer-frequent-shortcuts' = @{ State = 'Hidden'; Value = 0 }
      'windows.explorer-start-location' = @{ State = 'ThisPC'; Value = 1 }
      'windows.thumbnail-cache-creation' = @{ State = 'Disabled'; Value = 1 }
      'windows.network-thumbnail-database' = @{ State = 'Disabled'; Value = 1 }
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $planned = @(Get-RidePlan -Profile $defaultProfile)
    foreach ($id in $expected.Keys) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $id | Select-Object -First 1
      $operation | Should -Not -BeNullOrEmpty
      $desired = $expected[$id]
      $plannedOperation = $planned | Where-Object { $_.Operation.Id -eq $id } | Select-Object -First 1
      $plannedOperation.State | Should -Be $desired.State
      InModuleScope RIDE.Engine -Parameters @{ Id = $id; State = $desired.State; Value = $desired.Value } {
        param($Id, $State, $Value)
        $operation = Get-RideOperation -Id $Id
        Get-RideOperationValue -Operation $operation -State $State | Should -Be $Value
      }
    }
  }
}

Describe 'RIDE desired-state comparison' {
  It 'matches the inking and typing setting with its declared disabled value' {
    InModuleScope RIDE.Engine {
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 0; ValueType = 'DWord' } }
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      Test-RideDesiredState -Operation $operation -State 'Disabled' | Should -BeTrue
    }
  }

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
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Disabled' })

      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*simulated registry failure*'
    }
  }

  It 'applies the legacy disabled value through the registry handler' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideSettingState {}
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Disabled' })

      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke Set-RideSettingState -Exactly 1 -ParameterFilter { $Operation.Id -eq 'windows.inking-typing-data' -and $Value -eq 0 }
    }
  }

  It 'does not rewrite the inking and typing value when it is already disabled' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 0; ValueType = 'DWord' } }
      Mock Test-RideDesiredState { $true }
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideSettingState {}
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Disabled' })

      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Set-RideSettingState -Exactly 0
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
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
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

Describe 'RIDE Defender exclusion handler' {
  BeforeAll {
    Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-Defender.psm1') -Force
  }

  It 'reads an exclusion and reports its resolved path' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      Mock Get-RideDefenderExclusionPaths { @('C:\Tools') }
      $state = Get-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' }
      $state.Present | Should -BeTrue
      $state.Path | Should -Be 'C:\Tools'
    }
  }

  It 'adds an absent exclusion and leaves an already present exclusion unchanged' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      Mock Get-RideDefenderExclusionPaths { @('C:\Tools') }
      Mock Add-RideDefenderExclusion {}
      Mock Remove-RideDefenderExclusion {}
      Set-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -State Present
      Should -Invoke Add-RideDefenderExclusion -Exactly 0
      Should -Invoke Remove-RideDefenderExclusion -Exactly 0
    }
  }

  It 'adds the exclusion after preparing its managed directory' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      Mock Get-RideDefenderExclusionPaths { @() }
      Mock Test-Path { $true }
      Mock Add-RideDefenderExclusion {}
      Set-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -State Present
      Should -Invoke Add-RideDefenderExclusion -Exactly 1 -ParameterFilter { $Path -eq 'C:\Tools' }
    }
  }

  It 'removes an existing exclusion and restores captured membership' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      Mock Get-RideDefenderExclusionPaths { @('C:\Tools') }
      Mock Remove-RideDefenderExclusion {}
      Mock Add-RideDefenderExclusion {}
      Set-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -State Absent
      Should -Invoke Remove-RideDefenderExclusion -Exactly 1 -ParameterFilter { $Path -eq 'C:\Tools' }

      Mock Get-RideDefenderExclusionPaths { @() }
      Restore-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -Snapshot ([pscustomobject]@{ Present = $true; Path = 'C:\CapturedTools' })
      Should -Invoke Add-RideDefenderExclusion -Exactly 1 -ParameterFilter { $Path -eq 'C:\CapturedTools' }
    }
  }

  It 'propagates Defender command failures' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      Mock Get-RideDefenderExclusionPaths { @() }
      Mock Test-Path { $true }
      Mock Add-RideDefenderExclusion { throw 'simulated Defender failure' }
      { Set-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -State Present } | Should -Throw '*simulated Defender failure*'
    }
  }
}

Describe 'RIDE Defender exclusion planning and apply' {
  It 'includes both active default selectors as Present and classifies them as settings' {
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $plan = @(Get-RidePlan -Profile $defaultProfile)
    ($plan | Where-Object { $_.Operation.Kind -eq 'DefenderExclusion' }).Count | Should -Be 2
    ($plan | Where-Object { $_.Operation.Kind -eq 'DefenderExclusion' } | ForEach-Object State | Select-Object -Unique) | Should -Be 'Present'
    (Show-RideCatalog -View settings | Where-Object Kind -eq 'DefenderExclusion').Count | Should -Be 2
  }

  It 'plans direct set and unset states and compares live exclusion membership' {
    $setPlan = @(Get-RideSingleOperationPlan -Id 'windows.defender-tools-exclusion' -Action Set -State Present)
    $unsetPlan = @(Get-RideSingleOperationPlan -Id 'windows.defender-tools-exclusion' -Action Unset)
    $setPlan[0].State | Should -Be 'Present'
    $unsetPlan[0].State | Should -Be 'Absent'

    InModuleScope RIDE.Engine {
      Mock Get-RideCurrentState { [pscustomobject]@{ Present = $true; Path = 'C:\Tools' } }
      $operation = Get-RideOperation -Id 'windows.defender-tools-exclusion'
      Test-RideDesiredState -Operation $operation -State Present | Should -BeTrue
      Test-RideDesiredState -Operation $operation -State Absent | Should -BeFalse
    }
  }

  It 'applies through the mocked handler and does not mutate under WhatIf' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Present = $false; Path = 'C:\Tools' } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideDefenderExclusionState {}
      $operation = Get-RideOperation -Id 'windows.defender-tools-exclusion'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Present' })

      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Set-RideDefenderExclusionState -Exactly 0

      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke Set-RideDefenderExclusionState -Exactly 1 -ParameterFilter { $Operation.Id -eq 'windows.defender-tools-exclusion' -and $State -eq 'Present' }
    }
  }

  It 'reports a partial apply failure with the run ID and saved operation' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Present = $false; Path = 'C:\Tools' } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideDefenderExclusionState { throw 'simulated Defender write failure' }
      $operation = Get-RideOperation -Id 'windows.defender-tools-exclusion'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Present' })
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*simulated Defender write failure*'
    }
  }
}

Describe 'RIDE Windows service operations' {
  It 'plans the Hardening Windows defaults and classifies services as settings' {
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $plan = @(Get-RidePlan -Profile $defaultProfile)
    $servicePlan = @($plan | Where-Object { $_.Operation.Kind -eq 'WindowsService' })
    $servicePlan.Count | Should -Be 2
    ($servicePlan.State | Select-Object -Unique) | Should -Be 'Disabled'
    (Show-RideCatalog -View settings | Where-Object Kind -eq 'WindowsService').Count | Should -Be 2
  }

  It 'discovers service startup mode and running status' {
    InModuleScope RIDE-Services {
      Mock Get-Service { [pscustomobject]@{ Status = 'Stopped'; StartType = 'Manual' } }
      Mock Get-CimInstance { [pscustomobject]@{ StartMode = 'Manual' } }
      $state = Get-RideWindowsServiceState -Operation @{ ServiceName = 'SSDPSRV' }
      $state.StartupType | Should -Be 'Manual'
      $state.Status | Should -Be 'Stopped'
    }
  }

  It 'sets and restores both startup mode and running status' {
    InModuleScope RIDE-Services {
      $script:serviceStatus = 'Stopped'
      $script:serviceStartupType = 'Manual'
      Mock Get-Service { [pscustomobject]@{ Status = $script:serviceStatus; StartType = $script:serviceStartupType } }
      Mock Set-Service { $script:serviceStartupType = $StartupType }
      Mock Start-Service { $script:serviceStatus = 'Running' }
      Mock Stop-Service { $script:serviceStatus = 'Stopped' }
      $operation = @{ Id = 'test.service'; ServiceName = 'SSDPSRV'; States = @{ Enabled = @{ StartupType = 'Manual'; Status = 'Running' } } }
      Set-RideWindowsServiceState -Operation $operation -State Enabled
      Should -Invoke Start-Service -Exactly 1 -ParameterFilter { $Name -eq 'SSDPSRV' }
      Should -Invoke Set-Service -Exactly 0

      Restore-RideWindowsServiceState -Operation $operation -Snapshot ([pscustomobject]@{ StartupType = 'Disabled'; Status = 'Stopped' })
      Should -Invoke Set-Service -Exactly 1 -ParameterFilter { $Name -eq 'SSDPSRV' -and $StartupType -eq 'Disabled' }
      Should -Invoke Stop-Service -Exactly 1 -ParameterFilter { $Name -eq 'SSDPSRV' }
    }
  }

  It 'matches the declared Enabled and Disabled service configurations' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.ssdp-discovery-service'
      $enabled = [pscustomobject]@{ StartupType = 'Manual'; Status = 'Running' }
      $disabled = [pscustomobject]@{ StartupType = 'Disabled'; Status = 'Stopped' }
      Test-RideCurrentStateMatch -Operation $operation -State Enabled -CurrentState $enabled | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Disabled -CurrentState $disabled | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Enabled -CurrentState $disabled | Should -BeFalse
    }
  }

  It 'reports service-handler failures without swallowing them' {
    InModuleScope RIDE-Services {
      Mock Get-Service { throw 'simulated service manager failure' }
      { Get-RideWindowsServiceState -Operation @{ ServiceName = 'SSDPSRV' } } | Should -Throw '*simulated service manager failure*'
    }
  }
}

Describe 'RIDE UWP privacy policy migration' {
  It 'maps UWP privacy selectors to policy and capability registry operations' {
    $operation = $script:Catalog.Operations | Where-Object Id -eq 'windows.background-apps-policy'
    $operation.ValueName | Should -Be 'LetAppsRunInBackground'
    $operation.States.Disabled | Should -Be 2
    $operation.States.Enabled | Should -BeNullOrEmpty

    $policyOperations = @($script:Catalog.Operations | Where-Object Id -like 'windows.uwp-*' | Where-Object Kind -eq 'RegistryValue')
    $policyOperations.Count | Should -Be 19
    foreach ($policy in $policyOperations | Where-Object { $_.Id -notmatch 'documents-library|pictures-library|videos-library|file-system-access|swap-file' }) {
      $policy.States.Disabled | Should -Be 2
      $policy.States.Enabled | Should -BeNullOrEmpty
    }
    foreach ($id in @('windows.uwp-documents-library-access', 'windows.uwp-pictures-library-access', 'windows.uwp-videos-library-access', 'windows.uwp-broad-file-system-access-access')) {
      $policy = $script:Catalog.Operations | Where-Object Id -eq $id
      $policy.States.Denied | Should -Be 'Deny'
      $policy.States.Allowed | Should -Be 'Allow'
      $policy.States.UserControlled | Should -BeNullOrEmpty
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    ($defaultProfile.Operations | Where-Object Id -eq 'windows.background-apps-policy').State | Should -Be 'Disabled'
  }

  It 'provides direct set planning for the reversible per-app override reset' {
    $plan = @(Get-RideSingleOperationPlan -Id 'windows.uwp-background-app-user-overrides' -Action Set -State Reset)
    $plan[0].State | Should -Be 'Reset'
  }

  It 'captures, clears, and restores app-specific override values' {
    InModuleScope RIDE-BackgroundApps {
      $script:applicationKeys = @(
        [pscustomobject]@{ PSChildName = 'App.One'; PSPath = 'TestDrive:\App.One' }
      )
      $script:storedValues = @{ Disabled = 1; DisabledByUser = 1 }
      Mock Get-ChildItem { $script:applicationKeys }
      Mock Get-RideSettingState {
        param($Operation)
        if ($script:storedValues.ContainsKey($Operation.ValueName)) {
          [pscustomobject]@{ Exists = $true; Value = $script:storedValues[$Operation.ValueName]; ValueType = 'DWord' }
        }
        else { [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null } }
      }
      Mock Remove-ItemProperty { param($Name); $script:storedValues.Remove($Name) | Out-Null }
      Mock New-ItemProperty {}

      $operation = @{ RegistryPath = 'TestDrive:\BackgroundApps'; ValueNames = @('Disabled', 'DisabledByUser') }
      $state = Get-RideBackgroundAppOverrides -Operation $operation
      $state.Present | Should -BeTrue
      $state.Count | Should -Be 2
      Reset-RideBackgroundAppOverrides -Operation $operation
      Should -Invoke Remove-ItemProperty -Exactly 2

      $snapshot = [pscustomobject]@{ Overrides = @(
        [pscustomobject]@{ SubKey = 'App.One'; ValueName = 'Disabled'; Value = 1; ValueType = 'DWord' },
        [pscustomobject]@{ SubKey = 'App.One'; ValueName = 'DisabledByUser'; Value = 1; ValueType = 'DWord' }
      ) }
      Restore-RideBackgroundAppOverrides -Operation $operation -Snapshot $snapshot
      Should -Invoke New-ItemProperty -Exactly 2
    }
  }
}

Describe 'RIDE Security Tweaks default migration' {
  It 'plans the migrated registry and BCD defaults with explicit states' {
    $profile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $plan = @(Get-RidePlan -Profile $profile)
    $expected = @{
      'windows.admin-share-workstation' = 'Disabled'
      'windows.account-protection-warning' = 'Hidden'
      'windows.script-host-policy' = 'Disabled'
      'windows.dotnet-strong-crypto-64bit' = 'Enabled'
      'windows.dotnet-strong-crypto-32bit' = 'Enabled'
      'windows.f8-boot-menu-policy' = 'Legacy'
      'windows.dep-boot-policy' = 'OptOut'
    }
    foreach ($id in $expected.Keys) {
      ($plan | Where-Object { $_.Operation.Id -eq $id }).State | Should -Be $expected[$id]
    }
    ($script:Catalog.Operations | Where-Object Id -eq 'windows.admin-share-server').SupportedTargets | Should -Be 'Windows Server 2025'
  }

  It 'compares and names captured boot configuration states' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.f8-boot-menu-policy'
      $legacy = [pscustomobject]@{ Exists = $true; Value = 'Legacy' }
      $default = [pscustomobject]@{ Exists = $false; Value = $null }
      Test-RideCurrentStateMatch -Operation $operation -State Legacy -CurrentState $legacy | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Standard -CurrentState $default | Should -BeTrue
      Get-RideCurrentStateName -Operation $operation -CurrentState $legacy | Should -Be 'Legacy'
    }
  }

  It 'discovers BCD values and reports command errors' {
    InModuleScope RIDE-BootConfiguration {
      Mock bcdedit.exe { 'bootmenupolicy          Legacy'; $global:LASTEXITCODE = 0 }
      $operation = @{ BcdElement = 'bootmenupolicy' }
      $state = Get-RideBootConfigurationState -Operation $operation
      $state.Exists | Should -BeTrue
      $state.Value | Should -Be 'Legacy'

      Mock bcdedit.exe { 'Access is denied'; $global:LASTEXITCODE = 1 }
      { Get-RideBootConfigurationState -Operation $operation } | Should -Throw '*BCDEdit query failed*'
    }
  }
}
