<#
.SYNOPSIS
  Verify local firewall profiles, effective-policy reporting and bounded recovery.
.DESCRIPTION
  Every firewall, network and policy-key read/write is mocked. Engine state uses
  TestDrive. No live firewall, service, rule, network, VM or publisher API is changed.
.EXAMPLE
  Invoke-Pester ./tests/FirewallProfiles.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Add pending firewall-profile lifecycle and failure regression.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
}

Describe 'Firewall profile handler' {
  BeforeEach {
    InModuleScope RIDE-FirewallProfiles {
      $script:FirewallLocal = @{ Domain = 'False'; Private = 'True'; Public = 'False' }
      $script:FirewallEffective = @{ Domain = 'True'; Private = 'False'; Public = 'False' }
      $script:FirewallOperation = @{ Kind = 'FirewallProfile'; FirewallProfiles = @('Domain', 'Private', 'Public'); States = @{ On = 'True' } }
      Mock Get-NetFirewallProfile {
        $table = if ($PolicyStore -eq 'PersistentStore') { $script:FirewallLocal } elseif ($PolicyStore -eq 'ActiveStore') { $script:FirewallEffective } else { throw 'unexpected store' }
        foreach ($profileName in @($Name)) {
          if ($table.ContainsKey($profileName)) { [pscustomobject]@{ Name = $profileName; Enabled = $table[$profileName]; PolicyStoreSource = 'fixture source' } }
        }
      }
      Mock Set-NetFirewallProfile { $script:FirewallLocal[@($Name)[0]] = [string]$Enabled }
      Mock Get-NetConnectionProfile {
        @([pscustomobject]@{ Name = 'domain network'; InterfaceIndex = 1; NetworkCategory = 'DomainAuthenticated' },
          [pscustomobject]@{ Name = 'private network'; InterfaceIndex = 2; NetworkCategory = 'Private' })
      }
      Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like 'HKLM:*' }
    }
  }
  It 'reports local/effective conflict, concurrent networks and legacy-key presence without writes' {
    InModuleScope RIDE-FirewallProfiles {
      Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like 'HKLM:*' }
      $state = Get-RideFirewallProfileState $script:FirewallOperation
      $state.Entries.Count | Should -Be 3
      $state.Entries[0].Value | Should -Be 'False'
      $state.Entries[0].EffectiveValue | Should -Be 'True'
      $state.Entries[0].PolicyConflict | Should -BeTrue
      $state.Entries[0].Active | Should -BeTrue
      $state.Entries[1].Active | Should -BeTrue
      $state.Entries[2].Active | Should -BeFalse
      $state.LegacyStandardProfileKeyPresent | Should -BeTrue
      Should -Invoke Set-NetFirewallProfile -Times 0
    }
  }
  It 'enables all profiles idempotently through local Enabled-only writes' {
    InModuleScope RIDE-FirewallProfiles {
      $before = Get-RideFirewallProfileState $script:FirewallOperation
      Set-RideFirewallProfileState $script:FirewallOperation On $before
      Set-RideFirewallProfileState $script:FirewallOperation On
      Should -Invoke Set-NetFirewallProfile -Times 2 -Exactly -ParameterFilter { $PolicyStore -eq 'PersistentStore' -and [string]$Enabled -eq 'True' -and @($Name).Count -eq 1 }
      $script:FirewallLocal.Private | Should -Be 'True'
      $script:FirewallEffective.Private | Should -Be 'False'
    }
  }
  It 'restores mixed prior local flags and leaves effective policy untouched' {
    InModuleScope RIDE-FirewallProfiles {
      $before = Get-RideFirewallProfileState $script:FirewallOperation
      $snapshot = @{ SnapshotVersion = 1; PolicyStore = 'PersistentStore'; Entries = @($before.Entries | ForEach-Object { @{ Name = $_.Name; Value = $_.Value; ExpectedValue = 'True' } }) } | ConvertTo-Json -Depth 6 | ConvertFrom-Json
      Set-RideFirewallProfileState $script:FirewallOperation On
      Restore-RideFirewallProfileState $script:FirewallOperation $snapshot
      Restore-RideFirewallProfileState $script:FirewallOperation $snapshot
      $script:FirewallLocal.Domain | Should -Be 'False'
      $script:FirewallLocal.Private | Should -Be 'True'
      $script:FirewallLocal.Public | Should -Be 'False'
      Should -Invoke Set-NetFirewallProfile -Times 2 -Exactly -ParameterFilter { [string]$Enabled -eq 'False' -and $PolicyStore -eq 'PersistentStore' }
      $script:FirewallEffective.Domain | Should -Be 'True'
    }
  }
  It 'rejects unrecoverable local NotConfigured across the batch before its first write' {
    InModuleScope RIDE-FirewallProfiles {
      $script:FirewallLocal.Public = 'NotConfigured'
      (Get-RideFirewallProfileState $script:FirewallOperation).CanRestoreLocal | Should -BeFalse
      { Set-RideFirewallProfileState $script:FirewallOperation On } | Should -Throw '*not recoverable*no profile was changed*'
      Should -Invoke Set-NetFirewallProfile -Times 0
    }
  }
  It 'rejects capture drift before any write' {
    InModuleScope RIDE-FirewallProfiles {
      $before = Get-RideFirewallProfileState $script:FirewallOperation
      $script:FirewallLocal.Public = 'True'
      { Set-RideFirewallProfileState $script:FirewallOperation On $before } | Should -Throw '*changed after capture*'
      Should -Invoke Set-NetFirewallProfile -Times 0
    }
  }
  It 'reports partial completion, then recovers only changed local fields' {
    InModuleScope RIDE-FirewallProfiles {
      $before = Get-RideFirewallProfileState $script:FirewallOperation
      $snapshot = @{ SnapshotVersion = 1; PolicyStore = 'PersistentStore'; Entries = @($before.Entries | ForEach-Object { @{ Name = $_.Name; Value = $_.Value; ExpectedValue = 'True' } }) } | ConvertTo-Json -Depth 6 | ConvertFrom-Json
      Mock Set-NetFirewallProfile {
        if (@($Name)[0] -eq 'Public' -and [string]$Enabled -eq 'True') { throw 'fixture refusal' }
        $script:FirewallLocal[@($Name)[0]] = [string]$Enabled
      }
      { Set-RideFirewallProfileState $script:FirewallOperation On $before } | Should -Throw '*Public*Completed profiles: Domain, Private*fixture refusal*'
      Restore-RideFirewallProfileState $script:FirewallOperation $snapshot
      $script:FirewallLocal.Domain | Should -Be 'False'
      Should -Invoke Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { @($Name)[0] -eq 'Domain' -and [string]$Enabled -eq 'False' }
      Should -Invoke Set-NetFirewallProfile -Times 0 -ParameterFilter { @($Name)[0] -eq 'Private' }
    }
  }
  It 'detects local setter no-op instead of reporting a pass' {
    InModuleScope RIDE-FirewallProfiles {
      Mock Set-NetFirewallProfile {}
      { Set-RideFirewallProfileState $script:FirewallOperation On } | Should -Throw '*readback did not match*'
    }
  }
  It 'refuses missing profiles and inspection failures instead of inventing state' {
    InModuleScope RIDE-FirewallProfiles {
      $script:FirewallLocal.Remove('Public')
      { Get-RideFirewallProfileState $script:FirewallOperation } | Should -Throw '*missing or duplicated*'
      Mock Get-NetFirewallProfile { throw 'access denied fixture' }
      { Set-RideFirewallProfileState $script:FirewallOperation On } | Should -Throw '*access denied fixture*'
      Should -Invoke Set-NetFirewallProfile -Times 0
    }
  }
  It 'rejects <Problem> snapshots before writing' -ForEach @(
    @{ Problem = 'unknown version'; Version = 2; Store = 'PersistentStore'; Profile = 'Domain'; Value = 'False' },
    @{ Problem = 'effective store'; Version = 1; Store = 'ActiveStore'; Profile = 'Domain'; Value = 'False' },
    @{ Problem = 'wildcard profile'; Version = 1; Store = 'PersistentStore'; Profile = '*'; Value = 'False' },
    @{ Problem = 'unrestorable flag'; Version = 1; Store = 'PersistentStore'; Profile = 'Domain'; Value = 'NotConfigured' },
    @{ Problem = 'untyped flag'; Version = 1; Store = 'PersistentStore'; Profile = 'Domain'; Value = $false }
  ) {
    InModuleScope RIDE-FirewallProfiles -Parameters @{ Version = $Version; Store = $Store; Profile = $Profile; Value = $Value } {
      param($Version, $Store, $Profile, $Value)
      $script:FirewallOperation.FirewallProfiles = @('Domain')
      $snapshot = @{ SnapshotVersion = $Version; PolicyStore = $Store; Entries = @(@{ Name = $Profile; Value = $Value; ExpectedValue = 'True' }) }
      { Restore-RideFirewallProfileState $script:FirewallOperation $snapshot } | Should -Throw
      Should -Invoke Set-NetFirewallProfile -Times 0
    }
  }
  It 'rejects enable-all Off even if malformed metadata introduces it' {
    InModuleScope RIDE-FirewallProfiles {
      $script:FirewallOperation.States.Off = 'False'
      { Set-RideFirewallProfileState $script:FirewallOperation Off } | Should -Throw '*enablement only*'
      Should -Invoke Set-NetFirewallProfile -Times 0
    }
  }
}

Describe 'Firewall catalog and engine lifecycle' {
  It 'keeps all new operations pending and offers no local reset or recommended profile' {
    $operations = @((Get-RideCatalog).Operations | Where-Object Kind -eq 'FirewallProfile')
    $operations.Count | Should -Be 4
    foreach ($op in $operations) {
      $op.PendingAcceptance | Should -BeTrue
      $op.SupportedTargets.Count | Should -Be 0
      $op.States.Keys | Should -Not -Contain 'WindowsDefault'
      (Get-RideProfile).Operations.Id | Should -Not -Contain $op.Id
      { Get-RideSingleOperationPlan -Id $op.Id -Action Unset } | Should -Throw
    }
    @(Get-RideCatalogValidationErrors (Get-RideCatalog)).Count | Should -Be 0
    (Show-RideCatalog -View settings).Id | Should -Contain 'windows.firewall-domain-profiles'
  }
  It 'completes explicit states and reports configured/effective disagreement' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.firewall-public-profiles -State o"
    $completion = [Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches
    @($completion.CompletionText | Sort-Object) | Should -Be @('Off', 'On')
    InModuleScope RIDE.Engine {
      $op = Get-RideOperation windows.firewall-domain-profiles
      $current = [pscustomobject]@{ Available = $true; Entries = @(@{ Name = 'Domain'; Value = 'True'; EffectiveValue = 'False'; Active = $true; PolicyConflict = $true }) }
      Test-RideCurrentStateMatch $op On $current | Should -BeTrue
      Get-RideCurrentValueText $op $current | Should -Match 'local=True, effective=False.*policy conflict'
    }
  }
  It 'captures all prior flags before mutation and retains them after a partial failure' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'firewall-state') } {
      param($Root)
      $script:FirewallRoot = $Root
      $op = (Get-RideOperation windows.firewall-all-profiles).Clone()
      $op.SupportedTargets = @('Windows 11') # Fixture only; catalog remains pending.
      $plan = @([pscustomobject]@{ Operation = $op; State = 'On' })
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { $script:FirewallRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:FirewallRoot -Force | Out-Null; $script:FirewallRoot }
      Mock Get-RideCurrentState { [pscustomobject]@{ Available = $true; Entries = @(@{ Name = 'Domain'; Value = 'False' }, @{ Name = 'Private'; Value = 'True' }, @{ Name = 'Public'; Value = 'False' }) } }
      Mock Set-RideManagedSettingState {
        $records = @(Get-ChildItem -LiteralPath $script:FirewallRoot -Recurse -Filter windows.firewall-all-profiles.json)
        $saved = (Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json).Snapshot
        if ($saved.Entries.Count -ne 3) { throw 'incomplete capture' }
        if ($ExpectedState.Entries.Count -ne 3) { throw 'expected state was not passed' }
        throw 'fixture partial profile failure'
      }
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      Should -Invoke Set-RideManagedSettingState -Times 0
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*fixture partial profile failure*'
      $records = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter windows.firewall-all-profiles.json)
      $saved = (Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json).Snapshot
      $saved.PolicyStore | Should -Be 'PersistentStore'
      $saved.Entries[0].Value | Should -Be 'False'
      $saved.Entries[1].Value | Should -Be 'True'
      $saved.Entries[2].Value | Should -Be 'False'
    }
  }
  It 'blocks candidate apply without reading or changing live state' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideCurrentState { throw 'must not inspect candidate during blocked apply' }
      Mock Set-RideManagedSettingState {}
      $plan = @(Get-RideSingleOperationPlan windows.firewall-public-profiles Set Off)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*does not support*'
      Should -Invoke Get-RideCurrentState -Times 0
      Should -Invoke Set-RideManagedSettingState -Times 0
    }
  }
  It 'shows effective source in public show/plan/status and refuses empty desired-state matches' {
    Mock Get-RideCurrentState -ModuleName RIDE.Engine {
      [pscustomobject]@{ Available = $true; CanRestoreLocal = $true; ActiveNetworks = @(); LegacyStandardProfileKeyPresent = $false
        Entries = @(@{ Name = 'Domain'; Value = 'True'; EffectiveValue = 'False'; EffectiveSource = 'fixture source'; Active = $true; PolicyConflict = $true }) }
    }
    $profile = @{ SchemaVersion = 1; Name = 'Firewall display fixture'; Operations = @(@{ Id = 'windows.firewall-domain-profiles'; State = 'On' }) }
    (Show-RideOperation windows.firewall-domain-profiles | Out-String -Width 240) | Should -Match 'source: fixture source'
    (Show-RidePlan -Plan @(Get-RidePlan -Profile $profile) | Out-String -Width 240) | Should -Match 'source: fixture source'
    $status = @(Get-RideStatus -Profile $profile)[0]
    $status.EffectivePolicy | Should -Match 'differs from local configuration'
    $status.InDesiredState | Should -BeTrue
    InModuleScope RIDE.Engine {
      $op = Get-RideOperation windows.firewall-domain-profiles
      Test-RideCurrentStateMatch $op On ([pscustomobject]@{ Available = $true; Entries = @() }) | Should -BeFalse
    }
  }
  It 'rejects Boolean state payloads instead of coercing them into native enum names' {
    $catalog = Get-RideCatalog
    $op = $catalog.Operations | Where-Object Id -eq windows.firewall-domain-profiles
    $op.States.On = $true
    @(Get-RideCatalogValidationErrors $catalog) | Should -Contain "Firewall profile states are On/Off, or On only for all profiles: $($op.Id)"
    InModuleScope RIDE-FirewallProfiles {
      { Set-RideFirewallProfileState @{ Kind = 'FirewallProfile'; FirewallProfiles = @('Domain'); States = @{ On = $true } } On } | Should -Throw '*Unsupported firewall state*'
    }
  }
}
