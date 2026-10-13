<#
.SYNOPSIS
  Verify coordinated service startup, runtime, delay and compatible recovery.
.DESCRIPTION
  All service, CIM, native SCM and registry calls are mocked. State manifests use
  TestDrive. No VM, installer, network or developer-machine service is used.
.EXAMPLE
  Invoke-Pester ./tests/ServiceSettings.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Cover delayed-start, startup-only, exact recovery and failure stages.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
}

Describe 'Coordinated service configuration' {
  BeforeEach {
    InModuleScope RIDE-Services {
      $script:ServiceFixture = @{ Startup = 'Manual'; Status = 'Stopped'; Delay = $false;
        Raw = [pscustomobject]@{ KeyExisted = $true; Exists = $false; Value = $null; ValueType = $null } }
      $script:ServiceOperation = @{
        Id = 'test.service'; ServiceName = 'WSearch'; PreserveDelayedAutoStart = $true
        States = @{
          DelayedRunning = @{ StartupType = 'Automatic'; Status = 'Running'; DelayedAutoStart = $true }
          AutomaticRunning = @{ StartupType = 'Automatic'; Status = 'Running' }
          Disabled = @{ StartupType = 'Disabled'; Status = 'Stopped' }
          DelayedStartup = @{ StartupType = 'Automatic'; DelayedAutoStart = $true }
          AutomaticStartup = @{ StartupType = 'Automatic'; DelayedAutoStart = $false }
          ManualStartup = @{ StartupType = 'Manual' }
          DisabledStartup = @{ StartupType = 'Disabled' }
        }
      }
      Mock Get-Service { [pscustomobject]@{ Status = $script:ServiceFixture.Status; StartType = $script:ServiceFixture.Startup } }
      Mock Get-CimInstance { [pscustomobject]@{ StartMode = $(if ($script:ServiceFixture.Startup -eq 'Automatic') { 'Auto' } else { $script:ServiceFixture.Startup }) } }
      Mock Get-RideServiceDelayedAutoStart { $script:ServiceFixture.Delay }
      Mock Set-RideServiceDelayedAutoStart {
        $script:ServiceFixture.Delay = $Delayed
        $script:ServiceFixture.Raw = [pscustomobject]@{ KeyExisted = $true; Exists = $true; Value = [int]$Delayed; ValueType = 'DWord' }
      }
      Mock Get-RideSettingState { $script:ServiceFixture.Raw }
      Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like 'HKLM:*' }
      Mock Restore-RideSettingState { $script:ServiceFixture.Raw = $Snapshot }
      Mock Set-Service { $script:ServiceFixture.Startup = [string]$StartupType }
      Mock Start-Service { $script:ServiceFixture.Status = 'Running' }
      Mock Stop-Service { $script:ServiceFixture.Status = 'Stopped' }
      Mock Resume-Service { $script:ServiceFixture.Status = 'Running' }
      Mock Suspend-Service { $script:ServiceFixture.Status = 'Paused' }
    }
  }

  It 'captures service identity, SCM delay and literal absence without writes' {
    InModuleScope RIDE-Services {
      $before = Get-RideWindowsServiceState $script:ServiceOperation
      $before.SnapshotVersion | Should -Be 2
      $before.ServiceName | Should -Be 'WSearch'
      $before.EffectiveDelayedAutoStart | Should -BeFalse
      $before.DelayedAutoStart.Exists | Should -BeFalse
      $before.DelayedAutoStart.KeyExisted | Should -BeTrue
      Should -Invoke Set-Service -Times 0
      Should -Invoke Set-RideServiceDelayedAutoStart -Times 0
    }
  }
  It 'enriches the real registry-reader contract with key existence before saving recovery' {
    InModuleScope RIDE-Services {
      Mock Get-RideSettingState { [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null } }
      $before = Get-RideWindowsServiceState $script:ServiceOperation
      $before.DelayedAutoStart.KeyExisted | Should -BeTrue
      Restore-RideWindowsServiceState $script:ServiceOperation $before
      Should -Invoke Set-Service -Times 0
    }
  }
  It 'rejects unavailable service registry keys before configuration writes' {
    InModuleScope RIDE-Services {
      Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like 'HKLM:*' }
      { Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning } | Should -Throw '*Service registry key is unavailable*'
      Should -Invoke Set-Service -Times 0
    }
  }
  It 'configures delayed automatic startup before starting and is idempotent on repeat' {
    InModuleScope RIDE-Services {
      Mock Start-Service {
        if ($script:ServiceFixture.Startup -ne 'Automatic' -or -not $script:ServiceFixture.Delay) { throw 'wrong ordering' }
        $script:ServiceFixture.Status = 'Running'
      }
      Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning
      Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning
      Should -Invoke Set-Service -Exactly -Times 1
      Should -Invoke Set-RideServiceDelayedAutoStart -Exactly -Times 1 -ParameterFilter { $Delayed }
      Should -Invoke Start-Service -Exactly -Times 1
      Should -Invoke Restore-RideSettingState -Times 0
    }
  }
  It 'keeps a <Runtime> runtime for startup-only <Choice>' -ForEach @(
    @{ Runtime = 'Stopped'; Choice = 'DelayedStartup' },
    @{ Runtime = 'Running'; Choice = 'AutomaticStartup' },
    @{ Runtime = 'Paused'; Choice = 'ManualStartup' },
    @{ Runtime = 'Running'; Choice = 'DisabledStartup' }
  ) {
    InModuleScope RIDE-Services -Parameters @{ Runtime = $Runtime; Choice = $Choice } {
      param($Runtime, $Choice)
      $script:ServiceFixture.Status = $Runtime
      Set-RideWindowsServiceState $script:ServiceOperation $Choice
      $script:ServiceFixture.Status | Should -Be $Runtime
      Should -Invoke Start-Service -Times 0
      Should -Invoke Stop-Service -Times 0
      Should -Invoke Resume-Service -Times 0
      Should -Invoke Suspend-Service -Times 0
    }
  }
  It 'restores the dormant literal flag after startup normalization for <Choice>' -ForEach @(
    @{ Choice = 'AutomaticRunning' }, @{ Choice = 'Disabled' }
  ) {
    InModuleScope RIDE-Services -Parameters @{ Choice = $Choice } {
      param($Choice)
      $script:ServiceFixture.Delay = $true
      $script:ServiceFixture.Raw = [pscustomobject]@{ KeyExisted = $true; Exists = $true; Value = 7; ValueType = 'DWord' }
      Mock Set-Service {
        $script:ServiceFixture.Startup = [string]$StartupType
        $script:ServiceFixture.Delay = $false
        $script:ServiceFixture.Raw = [pscustomobject]@{ KeyExisted = $true; Exists = $true; Value = 0; ValueType = 'DWord' }
      }
      Set-RideWindowsServiceState $script:ServiceOperation $Choice
      $script:ServiceFixture.Delay | Should -BeTrue
      $script:ServiceFixture.Raw.Value | Should -Be 7
      Should -Invoke Restore-RideSettingState -Exactly -Times 1 -ParameterFilter { $Snapshot.Value -eq 7 }
    }
  }
  It 'recovers version-2 <Type> literal state and SCM delay through serialized snapshots' -ForEach @(
    @{ Type = 'Absent'; Exists = $false; Value = $null; ValueType = $null },
    @{ Type = 'DWord'; Exists = $true; Value = 7; ValueType = 'DWord' },
    @{ Type = 'String'; Exists = $true; Value = 'custom'; ValueType = 'String' }
  ) {
    InModuleScope RIDE-Services -Parameters @{ Exists = $Exists; Value = $Value; ValueType = $ValueType } {
      param($Exists, $Value, $ValueType)
      $script:ServiceFixture.Raw = [pscustomobject]@{ KeyExisted = $true; Exists = $Exists; Value = $Value; ValueType = $ValueType }
      $before = Get-RideWindowsServiceState $script:ServiceOperation | ConvertTo-Json -Depth 8 | ConvertFrom-Json
      Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning
      Restore-RideWindowsServiceState $script:ServiceOperation $before
      $after = Get-RideWindowsServiceState $script:ServiceOperation
      $after.StartupType | Should -Be 'Manual'
      $after.Status | Should -Be 'Stopped'
      $after.EffectiveDelayedAutoStart | Should -BeFalse
      $after.DelayedAutoStart.Exists | Should -Be $Exists
      $after.DelayedAutoStart.ValueType | Should -Be $ValueType
      $after.DelayedAutoStart.Value | Should -Be $Value
    }
  }
  It 'retains the unversioned raw-only recovery path' {
    InModuleScope RIDE-Services {
      $snapshot = @{ StartupType = 'Manual'; Status = 'Stopped'; DelayedAutoStart = @{ KeyExisted = $true; Exists = $true; Value = 7; ValueType = 'DWord' } } | ConvertTo-Json | ConvertFrom-Json
      Restore-RideWindowsServiceState $script:ServiceOperation $snapshot
      $script:ServiceFixture.Raw.Value | Should -Be 7
      Should -Invoke Set-RideServiceDelayedAutoStart -Times 0
    }
  }
  It 'recovers older raw-only records without key existence and never requests key deletion' {
    InModuleScope RIDE-Services {
      $script:ServiceFixture.Raw = [pscustomobject]@{ Exists = $true; Value = 1; ValueType = 'DWord'; KeyExisted = $true }
      $snapshot = @{ StartupType = 'Manual'; Status = 'Stopped'; DelayedAutoStart = @{ Exists = $false; Value = $null; ValueType = $null } } | ConvertTo-Json | ConvertFrom-Json
      Restore-RideWindowsServiceState $script:ServiceOperation $snapshot
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly -ParameterFilter { -not $Snapshot.Exists -and $Snapshot.KeyExisted -eq $true }
      $snapshot.DelayedAutoStart.PSObject.Properties.Name | Should -Not -Contain 'KeyExisted'
    }
  }
  It 'recovers disabled-but-running state through temporary Manual startup' {
    InModuleScope RIDE-Services {
      $script:ServiceFixture.Startup = 'Disabled'
      $script:ServiceFixture.Status = 'Running'
      $before = Get-RideWindowsServiceState $script:ServiceOperation
      Set-RideWindowsServiceState $script:ServiceOperation Disabled
      Mock Start-Service {
        if ($script:ServiceFixture.Startup -eq 'Disabled') { throw 'cannot start disabled service' }
        $script:ServiceFixture.Status = 'Running'
      }
      Restore-RideWindowsServiceState $script:ServiceOperation $before
      $script:ServiceFixture.Startup | Should -Be 'Disabled'
      $script:ServiceFixture.Status | Should -Be 'Running'
      Should -Invoke Set-Service -Times 1 -Exactly -ParameterFilter { $StartupType -eq 'Manual' }
    }
  }
  It 'rejects invalid literal recovery before temporary startup or runtime writes' {
    InModuleScope RIDE-Services {
      $snapshot = @{ StartupType = 'Disabled'; Status = 'Running'; DelayedAutoStart = @{ KeyExisted = $true; Exists = 'false' } }
      { Restore-RideWindowsServiceState $script:ServiceOperation $snapshot } | Should -Throw '*typed service delay snapshot*'
      Should -Invoke Set-Service -Times 0
      Should -Invoke Start-Service -Times 0
    }
  }
  It 'rejects <Problem> recovery before writes' -ForEach @(
    @{ Problem = 'unknown version'; Version = 99; Name = 'WSearch'; Delay = $true },
    @{ Problem = 'redirected identity'; Version = 2; Name = 'Other'; Delay = $true },
    @{ Problem = 'untyped SCM delay'; Version = 2; Name = 'WSearch'; Delay = 'false' }
  ) {
    InModuleScope RIDE-Services -Parameters @{ Version = $Version; Name = $Name; Delay = $Delay } {
      param($Version, $Name, $Delay)
      $snapshot = @{ SnapshotVersion = $Version; ServiceName = $Name; EffectiveDelayedAutoStart = $Delay; StartupType = 'Automatic'; Status = 'Running'; DelayedAutoStart = $script:ServiceFixture.Raw }
      { Restore-RideWindowsServiceState $script:ServiceOperation $snapshot } | Should -Throw '*snapshot*'
      Should -Invoke Set-Service -Times 0
      Should -Invoke Start-Service -Times 0
      Should -Invoke Set-RideServiceDelayedAutoStart -Times 0
    }
  }
  It 'rejects transition or missing service before writes' {
    InModuleScope RIDE-Services {
      $script:ServiceFixture.Status = 'StartPending'
      { Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning } | Should -Throw '*stable state*'
      Mock Get-Service { throw 'service missing' }
      { Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning } | Should -Throw '*missing*'
      Should -Invoke Set-Service -Times 0
    }
  }
  It 'rejects wildcard service identities before discovery' {
    InModuleScope RIDE-Services {
      $script:ServiceOperation.ServiceName = 'W*'
      { Get-RideWindowsServiceState $script:ServiceOperation } | Should -Throw '*identity*'
      Should -Invoke Get-Service -Times 0
    }
  }
  It 'reports delayed-start failure after startup and never starts the service' {
    InModuleScope RIDE-Services {
      Mock Set-RideServiceDelayedAutoStart { throw 'SCM refused' }
      { Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning } | Should -Throw '*delayed-start configuration*partial changes*SCM refused*'
      $script:ServiceFixture.Startup | Should -Be 'Automatic'
      Should -Invoke Start-Service -Times 0
    }
  }
  It 'reports runtime failure with startup/delay changes retained for saved-run recovery' {
    InModuleScope RIDE-Services {
      Mock Start-Service { throw 'dependency refused' }
      { Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning } | Should -Throw '*runtime*partial changes*dependency refused*'
      $script:ServiceFixture.Delay | Should -BeTrue
      Should -Invoke Stop-Service -Times 0
    }
  }
  It 'detects SCM no-op and stops before runtime' {
    InModuleScope RIDE-Services {
      Mock Set-RideServiceDelayedAutoStart {}
      { Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning } | Should -Throw '*readback*'
      Should -Invoke Start-Service -Times 0
    }
  }
  It 'detects literal restore failure rather than reporting exact recovery' {
    InModuleScope RIDE-Services {
      $before = Get-RideWindowsServiceState $script:ServiceOperation
      Set-RideWindowsServiceState $script:ServiceOperation DelayedRunning
      Mock Restore-RideSettingState {}
      { Restore-RideWindowsServiceState $script:ServiceOperation $before } | Should -Throw '*Literal delayed-start readback*'
    }
  }
}

Describe 'Service catalog, matching and read-only presentation' {
  It 'compiles native declarations without querying or changing services' {
    InModuleScope RIDE-Services {
      Initialize-RideServiceNativeApi
      ('Ride.ServiceDelayApi' -as [type]) | Should -Not -BeNullOrEmpty
    }
  }
  It 'declares choices on stable WAP Push/Search IDs without selecting them in default profiles' {
    foreach ($id in @('windows.wap-push-service', 'windows.search-indexing-service')) {
      $operation = Get-RideOperation $id
      $operation.States.AutomaticDelayedRunning.DelayedAutoStart | Should -BeTrue
      $operation.States.AutomaticRunning.ContainsKey('DelayedAutoStart') | Should -BeFalse
      $operation.States.Disabled.ContainsKey('DelayedAutoStart') | Should -BeFalse
      $operation.SupportedTargets | Should -Be @('Windows 11')
      (Get-RideProfile).Operations.Id | Should -Not -Contain $id
    }
  }
  It 'requires SCM delay for delayed states and distinguishes unknown/off/on' {
    InModuleScope RIDE.Engine {
      $op = Get-RideOperation 'windows.search-indexing-service'
      foreach ($flag in @($null, $false, $true)) {
        $current = [pscustomobject]@{ StartupType = 'Automatic'; Status = 'Running'; EffectiveDelayedAutoStart = $flag }
        Test-RideCurrentStateMatch $op AutomaticDelayedRunning $current | Should -Be ($flag -eq $true)
        Test-RideCurrentStateMatch $op AutomaticRunning $current | Should -BeTrue
      }
      Get-RideCurrentStateName $op ([pscustomobject]@{ StartupType = 'Automatic'; Status = 'Running'; EffectiveDelayedAutoStart = $true }) | Should -Be 'AutomaticDelayedRunning'
      Test-RideCurrentStateMatch $op ManualStartup ([pscustomobject]@{ StartupType = 'Manual'; Status = 'Paused' }) | Should -BeTrue
    }
  }
  It 'shows inactive SCM and raw delay separately and startup-only runtime preservation' {
    InModuleScope RIDE.Engine {
      $op = Get-RideOperation 'windows.search-indexing-service'
      $current = [pscustomobject]@{ StartupType = 'Disabled'; Status = 'Stopped'; EffectiveDelayedAutoStart = $true; DelayedAutoStart = @{ Exists = $true; Value = 7; ValueType = 'DWord' } }
      Get-RideCurrentValueText $op $current | Should -Match 'SCM delay: On \(inactive.*stored delay: 7 \(DWord\)'
      Get-RideServiceDesiredValueText $op.States.AutomaticDelayedStartup | Should -Be 'Automatic / Keep runtime; delay: On'
    }
  }
  It 'completes service states from the catalog, ignoring case and filtering the prefix' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.search-indexing-service -State automaticd"
    $matches = [Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches
    @($matches.CompletionText) | Should -Contain 'AutomaticDelayedRunning'
    @($matches.CompletionText) | Should -Contain 'AutomaticDelayedStartup'
    @($matches.CompletionText).Count | Should -Be 2
  }
  It 'shows live delay and explicit baseline in show and runtime preservation in plan/status' {
    Mock Get-RideCurrentState -ModuleName RIDE.Engine {
      [pscustomobject]@{ StartupType = 'Automatic'; Status = 'Running'; EffectiveDelayedAutoStart = $true;
        DelayedAutoStart = @{ Exists = $true; Value = 1; ValueType = 'DWord' } }
    }
    Mock Get-RidePlatform -ModuleName RIDE.Engine { 'Windows 11' }
    $details = Show-RideOperation windows.search-indexing-service | Out-String -Width 240
    $details | Should -Match 'SCM delay: On'
    $details | Should -Match 'BaselineValue\s+: Automatic / Running; delay: Preserve'
    $profile = @{ SchemaVersion = 1; Name = 'Service display fixture'; Operations = @(@{ Id = 'windows.search-indexing-service'; State = 'AutomaticDelayedStartup' }) }
    $plan = @(Get-RidePlan -Profile $profile)
    (Show-RidePlan -Plan $plan | Out-String -Width 240) | Should -Match 'Automatic / Keep runtime; delay: On'
    $status = @(Get-RideStatus -Profile $profile)
    $status.Count | Should -Be 1
    $status[0].DesiredValue | Should -Be 'Automatic / Keep runtime; delay: On'
    $status[0].InDesiredState | Should -BeTrue
  }
  It 'rejects malformed explicit delay, runtime and exact identities through shared validation' {
    foreach ($change in @('DelayType', 'DelayMode', 'DelayCapture', 'Status', 'Identity')) {
      $catalog = Get-RideCatalog
      $op = $catalog.Operations | Where-Object Id -eq 'windows.search-indexing-service'
      switch ($change) {
        DelayType { $op.States.AutomaticDelayedRunning.DelayedAutoStart = 'true' }
        DelayMode { $op.States.AutomaticDelayedRunning.StartupType = 'Manual' }
        DelayCapture { $op.PreserveDelayedAutoStart = $false }
        Status { $op.States.AutomaticDelayedRunning.Status = 'StartPending' }
        Identity { $op.ServiceName = 'W*' }
      }
      @(Get-RideCatalogValidationErrors $catalog).Count | Should -BeGreaterThan 0
    }
  }
}

Describe 'Service engine snapshots and preview' {
  BeforeEach {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) } {
      param($Root)
      $script:ServiceStateRoot = $Root
      $script:EngineServiceCurrent = [pscustomobject]@{
        SnapshotVersion = 2; ServiceName = 'WSearch'; StartupType = 'Manual'; Status = 'Stopped'
        EffectiveDelayedAutoStart = $false
        DelayedAutoStart = @{ KeyExisted = $true; Exists = $true; Value = 7; ValueType = 'DWord' }
      }
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { Join-Path $script:ServiceStateRoot $Scope }
      Mock Initialize-RideStateRoot {
        $path = Get-RideStateRoot -Scope $Scope
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $path
      }
      Mock Get-RideCurrentState { $script:EngineServiceCurrent }
      Mock Set-RideWindowsServiceState {
        $script:EngineServiceCurrent.StartupType = 'Automatic'
        $script:EngineServiceCurrent.Status = 'Running'
        $script:EngineServiceCurrent.EffectiveDelayedAutoStart = $true
      }
      Mock Restore-RideWindowsServiceState { $script:EngineServiceCurrent = $Snapshot }
    }
  }
  It 'captures version-2 raw/SCM state, previews without writes, skips repeat apply and previews recovery' {
    InModuleScope RIDE.Engine {
      $plan = @(Get-RideSingleOperationPlan -Id windows.search-indexing-service -Action Set -State AutomaticDelayedRunning)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path $script:ServiceStateRoot | Should -BeFalse
      Should -Invoke Set-RideWindowsServiceState -Times 0
      $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $runId = ($output | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
      $record = Get-Content -LiteralPath (Join-Path (Get-RideStateRoot Machine) "$runId/windows.search-indexing-service.json") -Raw | ConvertFrom-Json
      $record.Snapshot.SnapshotVersion | Should -Be 2
      $record.Snapshot.ServiceName | Should -Be 'WSearch'
      $record.Snapshot.EffectiveDelayedAutoStart | Should -BeFalse
      $record.Snapshot.DelayedAutoStart.Value | Should -Be 7
      @(Invoke-RidePlan -Plan $plan -Confirm:$false) | Should -Contain 'No changes were needed; no state record was created.'
      Should -Invoke Set-RideWindowsServiceState -Exactly -Times 1
      Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
      Should -Invoke Restore-RideWindowsServiceState -Times 0
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      Should -Invoke Restore-RideWindowsServiceState -Exactly -Times 1 -ParameterFilter { $Snapshot.SnapshotVersion -eq 2 -and $Snapshot.DelayedAutoStart.Value -eq 7 }
    }
  }
  It 'retains the complete pre-change record and run identity after a partial handler failure' {
    InModuleScope RIDE.Engine {
      Mock Set-RideWindowsServiceState { throw 'service partial failure fixture' }
      $plan = @(Get-RideSingleOperationPlan -Id windows.search-indexing-service -Action Set -State AutomaticDelayedRunning)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*service partial failure fixture*'
      $records = @(Get-ChildItem -LiteralPath (Get-RideStateRoot Machine) -Filter windows.search-indexing-service.json -Recurse)
      $records.Count | Should -Be 1
      $record = Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json
      $record.Snapshot.StartupType | Should -Be 'Manual'
      $record.Snapshot.EffectiveDelayedAutoStart | Should -BeFalse
      $record.Snapshot.DelayedAutoStart.Value | Should -Be 7
    }
  }
}
