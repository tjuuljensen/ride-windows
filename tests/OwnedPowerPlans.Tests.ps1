<#
.SYNOPSIS
  Verify owned power-plan creation, ownership failures and bounded recovery.
.DESCRIPTION
  All powercfg calls are mocked; ownership and export files use TestDrive. No
  developer power plan, active selection, package or disposable VM is changed.
.EXAMPLE
  Invoke-Pester ./tests/OwnedPowerPlans.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Add owned-copy lifecycle and engine capture regression.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
}

Describe 'Owned power-plan handler' {
  BeforeEach {
    InModuleScope RIDE-OwnedPowerPlans -Parameters @{ Root = (Join-Path $TestDrive ([guid]::NewGuid().ToString())) } {
      param($Root)
      $script:OwnedRoot = $Root
      $script:OwnedOp = @{ Id = 'windows.owned-balanced-power-plan'; Kind = 'OwnedPowerPlan'; Scope = 'Machine'; SourcePowerPlanGuid = '381b4222-f694-41f0-9685-ff5bb260df2e'; States = @{ Create = $true } }
      $script:PlanGuids = @($script:OwnedOp.SourcePowerPlanGuid)
      $script:PlanActive = $script:OwnedOp.SourcePowerPlanGuid
      $script:PlanExport = 'all-settings-export-fixture'
      Mock Invoke-RideOwnedPlanCommand {
        switch ($Arguments[0]) {
          '/list' { return [pscustomobject]@{ ExitCode = 0; Output = ($script:PlanGuids -join "`n") } }
          '/getactivescheme' { return [pscustomobject]@{ ExitCode = 0; Output = $script:PlanActive } }
          '/query' { return [pscustomobject]@{ ExitCode = 0; Output = $Arguments[1] } }
          '/duplicatescheme' {
            $intent = Get-RideOwnedPlanRecord $script:OwnedOp $script:OwnedRoot
            if ($intent.Stage -ne 'Intent' -or $intent.DestinationGuid -ne $Arguments[2]) { throw 'ownership intent must precede duplication' }
            $script:PlanGuids += $Arguments[2]
          }
          '/changename' { }
          '/export' { [IO.File]::WriteAllText($Arguments[1], $script:PlanExport) }
          '/delete' { $script:PlanGuids = @($script:PlanGuids | Where-Object { $_ -ne $Arguments[1] }) }
          default { throw "Unexpected native mutation: $($Arguments[0])" }
        }
        [pscustomobject]@{ ExitCode = 0; Output = '' }
      }
    }
  }
  It 'inspects absent ownership without files, exports or native mutation' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      $before.OriginalOwned | Should -BeFalse
      $before.Value | Should -BeFalse
      $before.DestinationGuid | Should -Not -Be $before.SourceGuid
      $before.ConfigurationComparison | Should -Match 'Not performed'
      Test-Path $script:OwnedRoot | Should -BeFalse
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -notin @('/list', '/query', '/getactivescheme') }
    }
  }
  It 'uses captured GUID and token, records intent before duplication and never activates' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot
      $record = Get-RideOwnedPlanRecord $script:OwnedOp $script:OwnedRoot
      $record.Stage | Should -Be 'Ready'
      $record.DestinationGuid | Should -Be $before.DestinationGuid
      $record.OwnerToken | Should -Be $before.OwnerToken
      $record.ExportSha256 | Should -Match '^[a-f0-9]{64}$'
      (Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot).Value | Should -BeTrue
      $script:PlanActive | Should -Be $before.SourceGuid
      @(Get-ChildItem -LiteralPath $script:OwnedRoot -Filter '*.pow').Count | Should -Be 0
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -eq '/setactive' }
    }
  }
  It 'does not duplicate if the ownership intent cannot be saved' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      Mock Write-RideOwnedPlanRecord { throw 'fixture ownership write denied' }
      { Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot } | Should -Throw '*ownership write denied*'
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -eq '/duplicatescheme' }
    }
  }
  It 'refuses concurrent ownership mutation through the exclusive lock' {
    InModuleScope RIDE-OwnedPowerPlans {
      $lock = Open-RideOwnedPlanLock $script:OwnedOp $script:OwnedRoot
      try { { Open-RideOwnedPlanLock $script:OwnedOp $script:OwnedRoot } | Should -Throw }
      finally { $lock.Dispose() }
    }
  }
  It 'rejects a reparse ownership path before native inspection' {
    InModuleScope RIDE-OwnedPowerPlans {
      New-Item -ItemType Directory -Path $script:OwnedRoot | Out-Null
      Mock Get-Item { [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint } } -ParameterFilter { $LiteralPath -eq $script:OwnedRoot }
      { Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot } | Should -Throw '*reparse points*'
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0
    }
  }
  It 'rejects oversized ownership records before native inspection' {
    InModuleScope RIDE-OwnedPowerPlans {
      New-Item -ItemType Directory -Path $script:OwnedRoot | Out-Null
      [IO.File]::WriteAllText((Get-RideOwnedPlanFile $script:OwnedOp $script:OwnedRoot), ('x' * 16385))
      { Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot } | Should -Throw '*16 KiB*'
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0
    }
  }
  It 'refuses unavailable source without duplication or ownership intent' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      Mock Invoke-RideOwnedPlanCommand { [pscustomobject]@{ ExitCode = 1; Output = '' } } -ParameterFilter { $Arguments[0] -eq '/query' }
      { Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot } | Should -Throw '*Source template is unavailable*'
      Get-RideOwnedPlanRecord $script:OwnedOp $script:OwnedRoot | Should -BeNullOrEmpty
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -eq '/duplicatescheme' }
    }
  }
  It 'never adopts a destination that appeared after capture' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      $script:PlanGuids += $before.DestinationGuid
      { Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot } | Should -Throw '*refusing to adopt*'
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -eq '/duplicatescheme' }
    }
  }
  It 'recovers only the unchanged inactive owned destination and permits a recovery retry' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot
      $saved = $before | ConvertTo-Json -Depth 8 | ConvertFrom-Json
      Restore-RideOwnedPowerPlanState $script:OwnedOp $saved $script:OwnedRoot
      Restore-RideOwnedPowerPlanState $script:OwnedOp $saved $script:OwnedRoot
      $script:PlanGuids | Should -Be @($before.SourceGuid)
      Get-RideOwnedPlanRecord $script:OwnedOp $script:OwnedRoot | Should -BeNullOrEmpty
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq '/delete' -and $Arguments[1] -eq $saved.DestinationGuid }
    }
  }
  It 'retains an active owned copy for selection recovery first' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot
      $script:PlanActive = $before.DestinationGuid
      { Restore-RideOwnedPowerPlanState $script:OwnedOp $before $script:OwnedRoot } | Should -Throw '*is active*'
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -in @('/delete', '/setactive') }
    }
  }
  It 'retains a changed export and cleans only temporary export files' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot
      $script:PlanExport = 'changed-hidden-or-visible-settings'
      { Restore-RideOwnedPowerPlanState $script:OwnedOp $before $script:OwnedRoot } | Should -Throw '*changed or native export is not reproducible*'
      @(Get-ChildItem -LiteralPath $script:OwnedRoot -Filter '*.pow').Count | Should -Be 0
      (Get-RideOwnedPlanRecord $script:OwnedOp $script:OwnedRoot).Stage | Should -Be 'Ready'
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -eq '/delete' }
    }
  }
  It 'retains incomplete ownership after <Stage> failure and refuses automatic deletion' -ForEach @(
    @{ Stage = 'duplicate'; Native = '/duplicatescheme' },
    @{ Stage = 'naming'; Native = '/changename' },
    @{ Stage = 'export'; Native = '/export' }
  ) {
    InModuleScope RIDE-OwnedPowerPlans -Parameters @{ Native = $Native } {
      param($Native)
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      $script:FailNative = $Native
      Mock Invoke-RideOwnedPlanCommand { [pscustomobject]@{ ExitCode = 1; Output = '' } } -ParameterFilter { $Arguments[0] -eq $script:FailNative }
      { Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot } | Should -Throw
      (Get-RideOwnedPlanRecord $script:OwnedOp $script:OwnedRoot).Stage | Should -Be 'Intent'
      { Restore-RideOwnedPowerPlanState $script:OwnedOp $before $script:OwnedRoot } | Should -Throw '*incomplete creation*'
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -eq '/delete' }
    }
  }
  It 'refuses an orphan even if its GUID matches the saved proposal' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      $script:PlanGuids += $before.DestinationGuid
      { Restore-RideOwnedPowerPlanState $script:OwnedOp $before $script:OwnedRoot } | Should -Throw '*without an ownership record*'
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -eq '/delete' }
    }
  }
  It 'refuses a different ownership token rather than trusting the destination alone' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot
      $before.OwnerToken = [guid]::NewGuid().ToString()
      { Restore-RideOwnedPowerPlanState $script:OwnedOp $before $script:OwnedRoot } | Should -Throw '*Ownership mismatch*'
      Should -Invoke Invoke-RideOwnedPlanCommand -Times 0 -ParameterFilter { $Arguments[0] -eq '/delete' }
    }
  }
  It 'retains ownership after failed deletion for a safe retry' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot
      Mock Invoke-RideOwnedPlanCommand { [pscustomobject]@{ ExitCode = 1; Output = '' } } -ParameterFilter { $Arguments[0] -eq '/delete' }
      { Restore-RideOwnedPowerPlanState $script:OwnedOp $before $script:OwnedRoot } | Should -Throw '*deletion failed*'
      (Get-RideOwnedPlanRecord $script:OwnedOp $script:OwnedRoot).Stage | Should -Be 'Ready'
    }
  }
  It 'refuses malformed or empty native identity enumeration' {
    InModuleScope RIDE-OwnedPowerPlans {
      Mock Invoke-RideOwnedPlanCommand { [pscustomobject]@{ ExitCode = 0; Output = 'no GUIDs' } } -ParameterFilter { $Arguments[0] -eq '/list' }
      { Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot } | Should -Throw '*no recognizable identities*'
    }
  }
  It 'rejects invalid captured identity before filesystem or native mutation' {
    InModuleScope RIDE-OwnedPowerPlans {
      $before = Get-RideOwnedPowerPlanState $script:OwnedOp $script:OwnedRoot
      $before.DestinationGuid = $before.SourceGuid
      { Set-RideOwnedPowerPlanState $script:OwnedOp Create $before $script:OwnedRoot } | Should -Throw '*Invalid captured*'
      Test-Path $script:OwnedRoot | Should -BeFalse
    }
  }
}

Describe 'Owned power-plan engine and catalog' {
  It 'keeps three creation candidates outside supported targets and recommended profiles' {
    $ops = @((Get-RideCatalog).Operations | Where-Object Kind -eq OwnedPowerPlan)
    $ops.Count | Should -Be 3
    foreach ($op in $ops) {
      $op.PendingAcceptance | Should -BeTrue
      $op.SupportedTargets.Count | Should -Be 0
      $op.Rollback | Should -Be 'Compensating'
      $op.States.Keys | Should -Be @('Create')
    }
    @(Get-RideCatalogValidationErrors (Get-RideCatalog)).Count | Should -Be 0
    (Show-RideCatalog -View settings).Id | Should -Contain 'windows.owned-balanced-power-plan'
  }
  It 'blocks pending candidates before live inspection even in preview' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideCurrentState { throw 'must not inspect blocked candidate' }
      $op = Get-RideOperation windows.owned-balanced-power-plan
      { Invoke-RidePlan -Plan @([pscustomobject]@{ Operation = $op; State = 'Create' }) -WhatIf -Confirm:$false } | Should -Throw '*does not support*'
      Should -Invoke Get-RideCurrentState -Times 0
    }
  }
  It 'saves the proposed destination and ownership token before mutation, including failure reporting' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'owned-engine') } {
      param($Root)
      $script:OwnedEngineRoot = $Root
      $script:OwnedCapture = [pscustomobject]@{ SnapshotVersion = 1; OperationId = 'windows.owned-balanced-power-plan'; SourceGuid = '381b4222-f694-41f0-9685-ff5bb260df2e'; DestinationGuid = [guid]::NewGuid().ToString(); OwnerToken = [guid]::NewGuid().ToString(); OriginalOwned = $false; OriginalRecord = $null; Value = $false; Available = $true; Stage = 'Absent' }
      $op = (Get-RideOperation windows.owned-balanced-power-plan).Clone()
      $op.SupportedTargets = @('Windows 11') # Fixture only; no target acceptance.
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { $script:OwnedEngineRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:OwnedEngineRoot -Force | Out-Null; $script:OwnedEngineRoot }
      Mock Get-RideCurrentState { $script:OwnedCapture }
      Mock Set-RideOwnedPowerPlanState {
        $files = @(Get-ChildItem -LiteralPath $script:OwnedEngineRoot -Recurse -Filter windows.owned-balanced-power-plan.json)
        $saved = (Get-Content -LiteralPath $files[0].FullName -Raw | ConvertFrom-Json).Snapshot
        if ($saved.DestinationGuid -ne $ExpectedState.DestinationGuid -or $saved.OwnerToken -ne $ExpectedState.OwnerToken) { throw 'capture did not precede creation' }
        if ($OwnershipRoot -ne (Join-Path $script:OwnedEngineRoot 'OwnedPowerPlans')) { throw 'incorrect trusted ownership root' }
        throw 'fixture partial creation failure'
      }
      $plan = @([pscustomobject]@{ Operation = $op; State = 'Create' })
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      Should -Invoke Set-RideOwnedPowerPlanState -Times 0
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*fixture partial creation failure*'
      Should -Invoke Set-RideOwnedPowerPlanState -Times 1 -Exactly
    }
  }
  It 'does not create another copy when a finalized owned copy already exists' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'owned-idempotent') } {
      param($Root)
      $script:OwnedIdempotentRoot = $Root
      $op = (Get-RideOperation windows.owned-balanced-power-plan).Clone()
      $op.SupportedTargets = @('Windows 11')
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { $script:OwnedIdempotentRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:OwnedIdempotentRoot -Force | Out-Null; $script:OwnedIdempotentRoot }
      Mock Get-RideCurrentState { [pscustomobject]@{ Available = $true; Value = $true; OriginalOwned = $true; DestinationExists = $true; Stage = 'Ready' } }
      Mock Set-RideOwnedPowerPlanState { throw 'must not repeat creation' }
      Invoke-RidePlan -Plan @([pscustomobject]@{ Operation = $op; State = 'Create' }) -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      Should -Invoke Set-RideOwnedPowerPlanState -Times 0
    }
  }
  It 'completes Create from the catalog and preserves published selection states' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.owned-balanced-power-plan -State c"
    @([Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches.CompletionText) | Should -Be @('Create')
    (Get-RideOperation windows.active-power-scheme).States.Keys | Sort-Object | Should -Be @('Balanced', 'HighPerformance')
  }
  It 'rejects destructive state/default or invalid-source metadata' {
    $catalog = Get-RideCatalog
    $op = $catalog.Operations | Where-Object Id -eq windows.owned-balanced-power-plan
    $op.States.Delete = $false
    $op.BaselineState = 'Create'
    $op.SourcePowerPlanGuid = 'balanced'
    @(Get-RideCatalogValidationErrors $catalog).Count | Should -BeGreaterThan 0
  }
}
