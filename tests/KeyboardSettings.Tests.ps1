<#
.SYNOPSIS
  Verify keyboard repeat-delay choices and compatibility with stored registry snapshots.
.DESCRIPTION
  Tests use catalog data and mocked registry access. No live keyboard setting,
  native setter, interactive input, publisher API or disposable VM is used.
.EXAMPLE
  Invoke-Pester ./tests/KeyboardSettings.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Cover four positions, completion and typed/absent legacy recovery.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
}

Describe 'Keyboard repeat-delay range and discovery' {
  It 'retains the registry backend, compatibility states and target boundary' {
    $op = Get-RideOperation windows.keyboard-repeat-delay
    $op.Kind | Should -Be 'RegistryValue'
    $op.Handler | Should -Be 'RegistryValue'
    $op.ValueType | Should -Be 'String'
    $op.Scope | Should -Be 'User'
    $op.RequiresAdmin | Should -BeFalse
    $op.States.Shortest | Should -BeExactly '0'
    $op.States.LegacyAppearance | Should -BeExactly '1'
    $op.States.Position2 | Should -BeExactly '2'
    $op.States.Longest | Should -BeExactly '3'
    $op.States.WindowsDefault | Should -BeNullOrEmpty
    $op.SupportedTargets | Should -Be @('Windows 11')
    $op.Description | Should -Match 'Stored state is not effective interactive-session readback'
    (Get-RideProfile).Operations.Id | Should -Not -Contain $op.Id
  }
  It 'plans each explicit position and retains override removal' {
    foreach ($state in @('Shortest', 'LegacyAppearance', 'Position2', 'Longest')) {
      $plan = @(Get-RideSingleOperationPlan -Id windows.keyboard-repeat-delay -Action Set -State $state)
      $plan.Count | Should -Be 1
      $plan[0].State | Should -Be $state
    }
    @(Get-RideSingleOperationPlan -Id windows.keyboard-repeat-delay -Action Unset)[0].State | Should -Be 'WindowsDefault'
    { Get-RideSingleOperationPlan -Id windows.keyboard-repeat-delay -Action Set -State Position4 } | Should -Throw
  }
  It 'completes the new choices from the catalog and filters without case sensitivity' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    foreach ($case in @(@{ Prefix = 'pos'; Choice = 'Position2' }, @{ Prefix = 'LONG'; Choice = 'Longest' })) {
      $line = "& '$path' set windows.keyboard-repeat-delay -State $($case.Prefix)"
      $completion = [Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches
      @($completion.CompletionText) | Should -Be @($case.Choice)
    }
  }
}

Describe 'Keyboard literal recovery compatibility' {
  It 'restores a serialized <Representation> without interpreting or coercing it into a chosen delay' -ForEach @(
    @{ Representation = 'legacy DWORD'; ValueType = 'DWord'; Value = 1 },
    @{ Representation = 'valid String'; ValueType = 'String'; Value = '3' },
    @{ Representation = 'unexpected String'; ValueType = 'String'; Value = 'custom prior preference' },
    @{ Representation = 'unexpected binary'; ValueType = 'Binary'; Value = @(7, 0, 255) }
  ) {
    InModuleScope RIDE-Settings -Parameters @{ Kind = $ValueType; Data = $Value } {
      param($Kind, $Data)
      $op = @{ RegistryPath = 'HKCU:\Control Panel\Keyboard'; ValueName = 'KeyboardDelay'; ValueType = 'String' }
      $snapshot = @{ KeyExisted = $true; Exists = $true; ValueType = $Kind; Value = $Data } | ConvertTo-Json -Depth 6 | ConvertFrom-Json
      Mock Test-Path { $true }
      Mock Get-RideSettingState { [pscustomobject]@{ Exists = $true; ValueType = 'String'; Value = '2' } }
      Mock New-ItemProperty {}
      Mock Remove-ItemProperty {}
      Mock Remove-Item {}
      Restore-RideSettingState -Operation $op -Snapshot $snapshot
      Should -Invoke New-ItemProperty -Times 1 -Exactly -ParameterFilter {
        $LiteralPath -eq $op.RegistryPath -and $Name -eq 'KeyboardDelay' -and
        $PropertyType -eq $Kind -and
        (ConvertTo-Json -InputObject $Value -Compress) -eq (ConvertTo-Json -InputObject $Data -Compress)
      }
      Should -Invoke Remove-Item -Times 0
      $op.ValueType | Should -Be 'String'
    }
  }
  It 'restores named-value absence and keeps an originally existing key' {
    InModuleScope RIDE-Settings {
      $op = @{ RegistryPath = 'HKCU:\Control Panel\Keyboard'; ValueName = 'KeyboardDelay'; ValueType = 'String' }
      Mock Remove-ItemProperty {}
      Mock Get-RideSettingState { [pscustomobject]@{ Exists = $true; KeyExisted = $true; Value = '2'; ValueType = 'String' } }
      Mock Get-Item { throw 'existing key must not be considered for deletion' }
      Mock Remove-Item {}
      Mock New-ItemProperty {}
      Restore-RideSettingState $op (@{ Exists = $false; KeyExisted = $true } | ConvertTo-Json | ConvertFrom-Json)
      Should -Invoke Remove-ItemProperty -Exactly -Times 1 -ParameterFilter { $LiteralPath -eq $op.RegistryPath -and $Name -eq 'KeyboardDelay' }
      Should -Invoke Remove-Item -Times 0
      Should -Invoke New-ItemProperty -Times 0
    }
  }
  It 'preserves unrelated values when the original key was absent' {
    InModuleScope RIDE-Settings {
      $op = @{ RegistryPath = 'HKCU:\Control Panel\Keyboard'; ValueName = 'KeyboardDelay'; ValueType = 'String' }
      $key = [pscustomobject]@{}
      $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @('KeyboardSpeed') }
      $key | Add-Member -MemberType ScriptMethod -Name GetSubKeyNames -Value { @() }
      Mock Get-Item { $key }
      Mock Get-RideSettingState { [pscustomobject]@{ Exists = $true; KeyExisted = $true; Value = '2'; ValueType = 'String' } }
      Mock Remove-ItemProperty {}
      Mock Remove-Item {}
      Restore-RideSettingState $op (@{ Exists = $false; KeyExisted = $false } | ConvertTo-Json | ConvertFrom-Json)
      Should -Invoke Remove-ItemProperty -Exactly -Times 1 -ParameterFilter { $Name -eq 'KeyboardDelay' }
      Should -Invoke Remove-Item -Times 0
    }
  }
  It 'captures typed old state before an apply failure and preserves preview isolation' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'keyboard-state') } {
      param($Root)
      $script:KeyboardStateRoot = $Root
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideStateRoot { $script:KeyboardStateRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:KeyboardStateRoot -Force | Out-Null; $script:KeyboardStateRoot }
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; ValueType = 'DWord'; Value = 1 } }
      Mock Get-Item { [pscustomobject]@{ ExistingKey = $true } } -ParameterFilter { $LiteralPath -eq 'HKCU:\Control Panel\Keyboard' }
      Mock Set-RideSettingState { throw 'keyboard fixture write failure' }
      $plan = @(Get-RideSingleOperationPlan -Id windows.keyboard-repeat-delay -Action Set -State Position2)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      Should -Invoke Set-RideSettingState -Times 0
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*keyboard fixture write failure*'
      $records = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter windows.keyboard-repeat-delay.json)
      $records.Count | Should -Be 1
      $snapshot = (Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json).Snapshot
      $snapshot.ValueType | Should -Be 'DWord'
      $snapshot.Value | Should -Be 1
      $snapshot.KeyExisted | Should -BeTrue
    }
  }
}
