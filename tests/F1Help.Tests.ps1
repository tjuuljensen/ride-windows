BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-RegistryValueSet.psm1') -Force
  $script:Catalog = Import-RideCatalogData -Path (Join-Path $PSScriptRoot '../catalog/operations.psd1')
  $script:Operation = @($script:Catalog.Operations | Where-Object Id -EQ 'windows.explorer-f1-help')[0]
}

Describe 'Experimental File Explorer F1 Help operation' {
  It 'is an explicitly pending per-user Windows 11 candidate selected by the default profile only' {
    $script:Operation.Kind | Should -Be 'RegistryValueSet'
    $script:Operation.Scope | Should -Be 'User'
    $script:Operation.RequiresAdmin | Should -BeFalse
    $script:Operation.SupportedTargets | Should -BeNullOrEmpty
    $script:Operation.CandidateTargets | Should -Contain 'Windows 11'
    $script:Operation.PendingAcceptance | Should -BeTrue
    $script:Operation.BaselineState | Should -Be 'WindowsDefault'
    $script:Operation.DocumentationUri | Should -Match '^https://support\.microsoft\.com/'
    $defaultProfile = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '../profiles/default.psd1')
    ($defaultProfile.Operations | Where-Object Id -eq $script:Operation.Id).State | Should -Be 'Blocked'
    foreach ($profileFile in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../profiles') -Filter '*.psd1' | Where-Object Name -ne 'default.psd1') {
      $profile = Import-PowerShellDataFile -LiteralPath $profileFile.FullName
      @($profile.Operations.Id) | Should -Not -Contain $script:Operation.Id
    }
  }

  It 'keeps default-profile application blocked on Windows 11 until the candidate is accepted' {
    $profile = Get-RideProfile -Path (Join-Path $PSScriptRoot '../profiles/default.psd1')
    $plan = @(Get-RidePlan -Profile $profile | Where-Object { $_.Operation.Id -eq $script:Operation.Id })
    $plan.Count | Should -Be 1
    ($plan | Where-Object { $_.Operation.Id -eq $script:Operation.Id }).State | Should -Be 'Blocked'
    InModuleScope RIDE.Engine -Parameters @{ Plan = $plan; OperationId = $script:Operation.Id } {
      param($Plan, $OperationId)
      Mock Get-RidePlatform { 'Windows 11' }
      { Assert-RidePlanAllowed -Plan $Plan } | Should -Throw "*$OperationId*does not support Windows 11*"
      Should -Invoke Get-RidePlatform -Times 1 -Exactly
    }
  }

  It 'declares only the two current-user unnamed TypeLib string values' {
    $script:Operation.RegistryValues.Count | Should -Be 2
    $script:Operation.RegistryValues[0].Key | Should -Be 'Win32'
    $script:Operation.RegistryValues[0].RegistryPath | Should -Match '^HKCU:\\Software\\Classes\\TypeLib\\\{8cec5860-07a1-11d9-b15e-000d56bfe6ee\}\\1\.0\\0\\win32$'
    $script:Operation.RegistryValues[1].Key | Should -Be 'Win64'
    $script:Operation.RegistryValues[1].RegistryPath | Should -Match '^HKCU:\\Software\\Classes\\TypeLib\\\{8cec5860-07a1-11d9-b15e-000d56bfe6ee\}\\1\.0\\0\\win64$'
    foreach ($member in $script:Operation.RegistryValues) {
      $member.ValueName | Should -Be ''
      $member.ValueType | Should -Be 'String'
    }
  }

  It 'maps Blocked to empty string overrides and WindowsDefault to removal' {
    $blocked = Get-RideRegistryValueSetEffectiveDesiredState -Operation $script:Operation -State 'Blocked'
    $blocked.Win32 | Should -BeExactly ''
    $blocked.Win64 | Should -BeExactly ''
    $default = Get-RideRegistryValueSetEffectiveDesiredState -Operation $script:Operation -State 'WindowsDefault'
    $default.Win32 | Should -BeNullOrEmpty
    $default.Win64 | Should -BeNullOrEmpty
  }

  It 'matches only a complete state across both architecture registrations' {
    $blockedState = [pscustomobject]@{ Values = @(
      [pscustomobject]@{ Key = 'Win32'; Exists = $true; Value = ''; ValueType = 'String'; KeyExisted = $true },
      [pscustomobject]@{ Key = 'Win64'; Exists = $true; Value = ''; ValueType = 'String'; KeyExisted = $true }
    ) }
    Test-RideRegistryValueSetMatch -Operation $script:Operation -State 'Blocked' -CurrentState $blockedState | Should -BeTrue
    $blockedState.Values[1].Exists = $false
    Test-RideRegistryValueSetMatch -Operation $script:Operation -State 'Blocked' -CurrentState $blockedState | Should -BeFalse
  }

  It 'writes both values through the focused handler for each declared state' {
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Operation = $script:Operation } {
      param($Operation)
      Mock Set-RideSettingState {}
      Set-RideRegistryValueSetState -Operation $Operation -State 'Blocked'
      Should -Invoke Set-RideSettingState -Times 2 -Exactly
      Should -Invoke Set-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.ValueName -eq '' -and $Value -ceq '' -and $Operation.RegistryPath -match '\\win32$' }
      Set-RideRegistryValueSetState -Operation $Operation -State 'WindowsDefault'
      Should -Invoke Set-RideSettingState -Times 4 -Exactly
      Should -Invoke Set-RideSettingState -Times 2 -Exactly -ParameterFilter { $null -eq $Value }
    }
  }

  It 'restores only the captured values through the handler in reverse order' {
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Operation = $script:Operation } {
      param($Operation)
      $script:RestoreOrder = @()
      Mock Restore-RideSettingState { $script:RestoreOrder += $Operation.RegistryPath }
      $snapshot = @{ Values = @(
        @{ Key = 'Win32'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $false },
        @{ Key = 'Win64'; Exists = $true; Value = 'previous'; ValueType = 'String'; KeyExisted = $true }
      ) }
      Restore-RideRegistryValueSetState -Operation $Operation -Snapshot $snapshot
      Should -Invoke Restore-RideSettingState -Times 2 -Exactly
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.RegistryPath -match '\\win64$' -and $Snapshot.Value -eq 'previous' }
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.RegistryPath -match '\\win32$' -and -not $Snapshot.Exists }
      $script:RestoreOrder.Count | Should -Be 2
      $script:RestoreOrder[0] | Should -Match '\\win64$'
      $script:RestoreOrder[1] | Should -Match '\\win32$'
    }
  }
}
