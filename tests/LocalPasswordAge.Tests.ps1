<#
.SYNOPSIS
  Verify local SAM maximum-age ranges, ownership, drift and exact raw recovery.
.DESCRIPTION
  All CIM and native policy calls are mocked. Native types may be compiled without
  calling Windows APIs. Catalog/state files use TestDrive; no VM, account policy,
  password, package or GitHub request is used.
.EXAMPLE
  Invoke-Pester ./tests/LocalPasswordAge.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Add bounded age states and focused native-field recovery.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogData.psm1') -Force
}
Describe 'Local maximum password age handler' {
  BeforeEach {
    $op = Get-RideOperation windows.local-password-maximum-age
    InModuleScope RIDE-LocalPasswordAge -Parameters @{ Op = $op } {
      param($Op)
      $script:AgeOperation = $Op
      $script:AgeRecord = @{ SamDomainSid = 'S-1-5-21-111-222-333'; MaxAgeSeconds = 42 * 86400; MinAgeSeconds = 86400; MinLength = 12; ForceLogoffSeconds = [uint32]::MaxValue; HistoryLength = 24 }
      Mock Get-CimInstance {
        if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{ ProductType = 1 } }
        if ($ClassName -eq 'Win32_ComputerSystem') { return [pscustomobject]@{ DomainRole = 0 } }
        throw 'unexpected CIM request'
      }
      Mock Get-RideLocalPasswordAgeNative { [pscustomobject]$script:AgeRecord.Clone() }
      Mock Set-RideLocalPasswordAgeNative { $script:AgeRecord.MaxAgeSeconds = $Seconds }
    }
  }
  It 'compiles the field-specific native ABI without invoking a policy read/write' {
    InModuleScope RIDE-LocalPasswordAge {
      Initialize-RideLocalPasswordAgeApi
      [Runtime.InteropServices.Marshal]::SizeOf([type][Ride.UserModals1002]) | Should -Be 4
      [Runtime.InteropServices.Marshal]::SizeOf([type][Ride.UserModals0]) | Should -Be 20
      Should -Invoke Get-RideLocalPasswordAgeNative -Times 0
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 0
    }
  }
  It 'reads currently applied nonsecret SAM data without writes or policy-source claims' {
    InModuleScope RIDE-LocalPasswordAge {
      $current = Get-RideLocalPasswordAgeState $script:AgeOperation
      $current.Value | Should -Be 42
      $current.Interpretation | Should -Be '42 days'
      $current.EffectivePolicy | Should -Match 'managed source not inspected'
      $current.Policy.MinLength | Should -Be 12
      $current.Policy.PSObject.Properties.Name | Should -Not -Contain 'Password'
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 0
    }
  }
  It 'sets explicit days and Never expires while preserving every other modal field' {
    InModuleScope RIDE-LocalPasswordAge {
      $before = Get-RideLocalPasswordAgeState $script:AgeOperation
      Set-RideLocalPasswordAgeState $script:AgeOperation Days90 $before
      $script:AgeRecord.MaxAgeSeconds | Should -Be (90 * 86400)
      $after = Get-RideLocalPasswordAgeState $script:AgeOperation
      Test-RideLocalPasswordAgeContext $before.Policy $after.Policy | Should -BeTrue
      Set-RideLocalPasswordAgeState $script:AgeOperation NoExpiry $after
      $script:AgeRecord.MaxAgeSeconds | Should -Be ([uint32]::MaxValue)
      (Get-RideLocalPasswordAgeState $script:AgeOperation).Value | Should -Be 0
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 2 -Exactly
    }
  }
  It 'does not write again when the exact maximum age already matches' {
    InModuleScope RIDE-LocalPasswordAge {
      $before = Get-RideLocalPasswordAgeState $script:AgeOperation
      Set-RideLocalPasswordAgeState $script:AgeOperation Days42 $before
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 0
    }
  }
  It 'refuses a maximum age equal to or below current minimum age before writes' {
    InModuleScope RIDE-LocalPasswordAge {
      $script:AgeRecord.MinAgeSeconds = 30 * 86400
      $before = Get-RideLocalPasswordAgeState $script:AgeOperation
      foreach ($state in @('Days1','Days30')) {
        { Set-RideLocalPasswordAgeState $script:AgeOperation $state $before } | Should -Throw '*greater than the current minimum age*'
      }
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 0
    }
  }
  It 'refuses domain controllers before native policy inspection' {
    InModuleScope RIDE-LocalPasswordAge {
      Mock Get-CimInstance {
        if ($ClassName -eq 'Win32_OperatingSystem') { [pscustomobject]@{ ProductType = 2 } }
        else { [pscustomobject]@{ DomainRole = 5 } }
      }
      { Get-RideLocalPasswordAgeState $script:AgeOperation } | Should -Throw '*Domain-controller*'
      Should -Invoke Get-RideLocalPasswordAgeNative -Times 0
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 0
    }
  }
  It 'refuses missing or inconsistent role evidence instead of choosing local authority' {
    InModuleScope RIDE-LocalPasswordAge {
      Mock Get-CimInstance { [pscustomobject]@{} }
      { Get-RideLocalPasswordAgeState $script:AgeOperation } | Should -Throw '*unknown or inconsistent*'
      Should -Invoke Get-RideLocalPasswordAgeNative -Times 0
    }
  }
  It 'refuses changed modal context after capture before using the focused setter' {
    InModuleScope RIDE-LocalPasswordAge {
      $before = Get-RideLocalPasswordAgeState $script:AgeOperation
      $script:AgeRecord.HistoryLength = 25
      { Set-RideLocalPasswordAgeState $script:AgeOperation Days90 $before } | Should -Throw '*changed after capture*'
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 0
    }
  }
  It 'reports a native setter failure without claiming application success' {
    InModuleScope RIDE-LocalPasswordAge {
      $before = Get-RideLocalPasswordAgeState $script:AgeOperation
      Mock Set-RideLocalPasswordAgeNative { throw 'fixture access denied' }
      { Set-RideLocalPasswordAgeState $script:AgeOperation Days90 $before } | Should -Throw '*fixture access denied*'
      $script:AgeRecord.MaxAgeSeconds | Should -Be (42 * 86400)
    }
  }
  It 'reports post-write drift rather than replaying unrelated policy fields' {
    InModuleScope RIDE-LocalPasswordAge {
      $before = Get-RideLocalPasswordAgeState $script:AgeOperation
      Mock Set-RideLocalPasswordAgeNative { $script:AgeRecord.MaxAgeSeconds = $Seconds; $script:AgeRecord.MinLength = 15 }
      { Set-RideLocalPasswordAgeState $script:AgeOperation Days90 $before } | Should -Throw '*unrelated policy context changed*'
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 1 -Exactly
    }
  }
  It 'recovers exact raw seconds including a valid prior value outside day presets' {
    InModuleScope RIDE-LocalPasswordAge {
      $script:AgeRecord.MaxAgeSeconds = 42 * 86400 + 7
      $before = Get-RideLocalPasswordAgeState $script:AgeOperation
      $before.Value | Should -BeNullOrEmpty
      Set-RideLocalPasswordAgeState $script:AgeOperation Days90 $before
      $saved = @{ SnapshotVersion = 1; OperationId = $script:AgeOperation.Id; Prior = $before.Policy; ExpectedMaxAgeSeconds = 90 * 86400 } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
      Restore-RideLocalPasswordAgeState $script:AgeOperation $saved
      Restore-RideLocalPasswordAgeState $script:AgeOperation $saved
      $script:AgeRecord.MaxAgeSeconds | Should -Be (42 * 86400 + 7)
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 2 -Exactly
    }
  }
  It 'refuses stale <Conflict> recovery without changing policy' -ForEach @(
    @{ Conflict = 'authority'; Field = 'SamDomainSid'; Value = 'S-1-5-21-444-555-666' },
    @{ Conflict = 'maximum age'; Field = 'MaxAgeSeconds'; Value = 60 * 86400 },
    @{ Conflict = 'minimum age'; Field = 'MinAgeSeconds'; Value = 14 * 86400 }
  ) {
    InModuleScope RIDE-LocalPasswordAge -Parameters @{ Field = $Field; Value = $Value } {
      param($Field,$Value)
      $before = Get-RideLocalPasswordAgeState $script:AgeOperation
      Set-RideLocalPasswordAgeState $script:AgeOperation Days90 $before
      $snapshot = @{ SnapshotVersion = 1; OperationId = $script:AgeOperation.Id; Prior = $before.Policy; ExpectedMaxAgeSeconds = 90 * 86400 }
      $script:AgeRecord[$Field] = $Value
      { Restore-RideLocalPasswordAgeState $script:AgeOperation $snapshot } | Should -Throw
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 1 -Exactly
    }
  }
  It 'rejects malformed snapshots and unrepresentable prior values before writes' {
    InModuleScope RIDE-LocalPasswordAge {
      $before = Get-RideLocalPasswordAgeState $script:AgeOperation
      $snapshot = @{ SnapshotVersion = 1; OperationId = $script:AgeOperation.Id; Prior = $before.Policy; ExpectedMaxAgeSeconds = -1 }
      { Restore-RideLocalPasswordAgeState $script:AgeOperation $snapshot } | Should -Throw '*Invalid expected*'
      $snapshot.ExpectedMaxAgeSeconds = 90 * 86400
      $snapshot.SnapshotVersion = 2
      { Restore-RideLocalPasswordAgeState $script:AgeOperation $snapshot } | Should -Throw '*identity/version*'
      $snapshot.SnapshotVersion = 1
      $snapshot.OperationId = 'other.operation'
      { Restore-RideLocalPasswordAgeState $script:AgeOperation $snapshot } | Should -Throw '*identity/version*'
      $script:AgeRecord.MaxAgeSeconds = 0
      { Get-RideLocalPasswordAgeState $script:AgeOperation } | Should -Throw '*cannot be safely recovered*'
      Should -Invoke Set-RideLocalPasswordAgeNative -Times 0
    }
  }
}

Describe 'Local maximum password age catalog and engine' {
  It 'derives the full bounded state set and rejects invalid range metadata without execution' {
    $op = Get-RideOperation windows.local-password-maximum-age
    $op.States.Count | Should -Be 1000
    $op.States.Days1 | Should -Be 1
    $op.States.Days999 | Should -Be 999
    $op.States.NoExpiry | Should -Be 0
    $op.SupportedTargets.Count | Should -Be 0
    $op.PendingAcceptance | Should -BeTrue
    (Get-RideProfile).Operations.Id | Should -Not -Contain $op.Id
    @(Get-RideCatalogValidationErrors (Get-RideCatalog)).Count | Should -Be 0
    $fixture = Join-Path $TestDrive 'bad-range.psd1'
    [IO.File]::WriteAllText($fixture, "@{SchemaVersion=1; Operations=@(@{Kind='LocalPasswordMaximumAge'; States=@{NoExpiry=0}; StateRange=@{Prefix='Days';Minimum=1;Maximum=100000}});Groups=@()}")
    { Import-RideCatalogData $fixture } | Should -Throw '*Invalid bounded*'
  }
  It 'completes explicit days from the same catalog as execution without live inspection' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.local-password-maximum-age -State days99"
    $matches = @([Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches.CompletionText)
    $matches.Count | Should -Be 11
    $matches | Should -Contain 'Days99'
    $matches | Should -Contain 'Days999'
    @($matches | Sort-Object -Unique).Count | Should -Be $matches.Count
    { Get-RideSingleOperationPlan -Id windows.local-password-maximum-age -Action Unset } | Should -Throw '*no declared override-removal state*'
  }
  It 'blocks the candidate before any native inspection or mutation' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideCurrentState { throw 'candidate must not be inspected' }
      Mock Set-RideLocalPasswordAgeState {}
      $plan = @(Get-RideSingleOperationPlan -Id windows.local-password-maximum-age -Action Set -State Days90)
      { Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false } | Should -Throw '*does not support*'
      Should -Invoke Get-RideCurrentState -Times 0
      Should -Invoke Set-RideLocalPasswordAgeState -Times 0
    }
  }
  It 'captures exact raw prior context and expected seconds before a failed field write' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'age-engine') } {
      param($Root)
      $script:AgeRoot = $Root
      $op = (Get-RideOperation windows.local-password-maximum-age).Clone()
      $op.SupportedTargets = @('Windows 11') # Fixture only; catalog remains pending.
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { $script:AgeRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:AgeRoot -Force | Out-Null; $script:AgeRoot }
      Mock Get-RideCurrentState { [pscustomobject]@{ Available = $true; GuiCompatible = $false; Value = $null; Policy = @{ SamDomainSid = 'S-1-5-21-111-222-333'; MaxAgeSeconds = 42*86400+7; MinAgeSeconds = 86400; MinLength = 12; HistoryLength = 24; ForceLogoffSeconds = [long][uint32]::MaxValue } } }
      Mock Set-RideLocalPasswordAgeState {
        $file = @(Get-ChildItem -LiteralPath $script:AgeRoot -Recurse -Filter windows.local-password-maximum-age.json)[0]
        $snapshot = (Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json).Snapshot
        if ($snapshot.Prior.MaxAgeSeconds -ne $ExpectedState.Policy.MaxAgeSeconds -or $snapshot.ExpectedMaxAgeSeconds -ne 90*86400) { throw 'missing exact capture' }
        throw 'fixture native field failure'
      }
      $plan = @([pscustomobject]@{ Operation = $op; State = 'Days90' })
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*fixture native field failure*'
      Should -Invoke Set-RideLocalPasswordAgeState -Times 1 -Exactly
    }
  }
}
