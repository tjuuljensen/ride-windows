<#
.SYNOPSIS
  Verify the disposable hibernation acceptance workflow using simulated state.
.DESCRIPTION
  Mocks every guest, registry, native command and engine mutation boundary.
  Does not start a VM, run powercfg, access live registry or queue controller work.
.EXAMPLE
  Invoke-Pester ./tests/HibernationAcceptance.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Version: repository test fixture. Changelog: 2026-11-01: Add acceptance routing,
  matrix, conditional recovery, preview and preflight failure coverage.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.HibernationAcceptance.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.SettingsFixtureData.psm1') -Force
}

Describe 'Request-bound hibernation matrix routing' {
  It 'accepts the six-state template only after binding its request identity' {
    $source = Join-Path $PSScriptRoot 'integration/fixtures/hibernation.fixture.psd1'
    $path = Join-Path $TestDrive 'bound.psd1'
    $runId = '0123456789abcdef0123456789abcdef'
    { Read-RideSettingsFixture $source ('0' * 32) SettingsBatch60 (Join-Path $PSScriptRoot '../catalog/operations.psd1') } | Should -Throw
    $text = [IO.File]::ReadAllText($source).Replace(('0' * 32), $runId)
    [IO.File]::WriteAllText($path, $text)
    $data = Read-RideSettingsFixture $path $runId SettingsBatch60 (Join-Path $PSScriptRoot '../catalog/operations.psd1')
    $data.Operation.Id | Should -Be windows.hibernation
    $data.Operation.SupportedTargets.Count | Should -Be 0
    $data.Fixture.States.Count | Should -Be 6
    Get-RideSettingsFixtureScenario | Should -Contain HibernationMatrix
    foreach ($bad in @(
      $text.Replace("Target = 'Windows 11'", "Target = 'Windows Server 2025'"),
      $text.Replace("Scenario = 'HibernationMatrix'", "Scenario = 'Lifecycle'"),
      $text.Replace("OperationId = 'windows.hibernation'", "OperationId = 'windows.local-password-maximum-age'"),
      $text.Replace("'Size100'", "'Size101'"),
      $text.Replace('AllowPendingCandidate = $true', 'AllowPendingCandidate = $false'),
      $text.Replace("'SettingsBatch60'", "'SettingsBatch40'"),
      $text.Replace('SchemaVersion = 2', 'SchemaVersion = 1')
    )) {
      [IO.File]::WriteAllText($path, $bad)
      { Read-RideSettingsFixture $path $runId SettingsBatch60 (Join-Path $PSScriptRoot '../catalog/operations.psd1') } | Should -Throw
    }
  }
  It 'routes hibernation after private catalog preparation and retains failed recovery material' {
    $runner = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'integration/Invoke-RideSettingsFixture.ps1') -Raw
    $runner.IndexOf('Invoke-RideHibernationAcceptance -Operation') | Should -BeGreaterThan $runner.IndexOf('Import-Module (Join-Path $privateRoot')
    $runner | Should -Match "operation.Kind -eq 'Hibernation' -and \`$report.Status -ne 'Passed'"
    $guest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'integration/Invoke-RideGuestTests.ps1') -Raw
    $guest | Should -Match "Hibernation \{ \`$names = @\('Hibernation.Tests.ps1','HibernationAcceptance.Tests.ps1','SettingsFixtureData.Tests.ps1','CliShouldProcess.Tests.ps1'\)"
    & (Join-Path $PSScriptRoot 'integration/Invoke-RideSettingsFixture.ps1') -Version | Should -Be '0.13.0'
    & (Join-Path $PSScriptRoot 'integration/Invoke-RideGuestTests.ps1') -Version | Should -Be '1.10.0'
  }
}

Describe 'Hibernation acceptance orchestration without Windows mutations' {
  BeforeEach {
    InModuleScope RIDE.HibernationAcceptance -Parameters @{ Root = $TestDrive } {
      param($Root)
      $script:AcceptanceRoot = Join-Path $Root ([guid]::NewGuid().ToString('N'))
      $null = New-Item -ItemType Directory -Path (Join-Path $script:AcceptanceRoot 'modules') -Force
      foreach ($name in @('RIDE-Hibernation.psm1','RIDE.Engine.psm1')) { Set-Content -LiteralPath (Join-Path $script:AcceptanceRoot ('modules/' + $name)) -Value '# Synthetic hash fixture only' }
      $script:AcceptanceEvidence = Join-Path $script:AcceptanceRoot 'evidence.json'
      $script:AcceptanceOperation = @{ Id = 'windows.hibernation'; Kind = 'Hibernation' }
      $script:AcceptanceReport = [ordered]@{ RunId = 'a' * 32; SavedRunIds = @(); Original = $null; Restored = $null; LifecyclePassed = $false; RecoveryPassed = $false; ExactRecovery = $false; Error = $null; RecoveryError = $null }
      $script:SimState = [pscustomobject]@{ Available = $true; Observation = [pscustomobject]@{ Mode = 'Full'; SizePercent = 75; FileBytes = 1024L; HibernateAvailable = $true } }
      $script:SimSaved = @{}; $script:SimNext = 1
      $script:SimCalls = [Collections.Generic.List[object]]::new()
      $script:SimInterrupt = $false; $script:SimRecoveryFails = $false; $script:SimPreviewWrites = $false
      function script:Copy-SimState { $script:SimState | ConvertTo-Json -Depth 5 | ConvertFrom-Json }
      Mock Assert-RideHibernationAcceptanceGuest {}
      Mock Get-HibernationAcceptancePlatform { @{ FreeBytes = 10GB; PhysicalMemoryBytes = 1GB; Build = 'fixture'; PowerShell = 'fixture' } }
      Mock Get-HibernationAcceptancePreferences { 'unchanged preferences and scheme' }
      Mock Invoke-HibernationReadOnlyPowercfg { 'Synthetic diagnostics; no Windows query' }
      Mock Get-HibernationAcceptanceRuns { @($script:SimSaved.Keys | Sort-Object) }
      Mock Get-RideCurrentState { Copy-SimState }
      Mock Get-RideSingleOperationPlan { param($Id,$Action,$State) [pscustomobject]@{ State = $State } }
      Mock Test-RideDesiredState {
        param($Operation,$State)
        if ($State -match '^Size([0-9]+)$') { return ($script:SimState.Observation.Mode -eq 'Full' -and $script:SimState.Observation.SizePercent -eq [int]$Matches[1]) }
        return $script:SimState.Observation.Mode -eq $State
      }
      Mock Invoke-RidePlan {
        param($Plan, [switch]$WhatIf)
        if ($WhatIf) { if ($script:SimPreviewWrites) { $script:SimCalls.Add('bad preview write') }; return }
        $state = $Plan[0].State
        if (Test-RideDesiredState -Operation $script:AcceptanceOperation -State $state) { return 'No changes were needed; no state record was created.' }
        $id = $script:SimNext.ToString('x32'); $script:SimNext++
        $script:SimSaved[$id] = Copy-SimState
        $script:SimCalls.Add($state)
        if ($state -eq 'Reduced' -and $script:SimInterrupt) {
          $script:SimState.Observation.Mode = 'Full'; $script:SimState.Observation.SizePercent = 40
          $script:SimInterrupt = $false
          throw "Run ID: $id. RIDE hibernation fixture interruption after successful native size reset."
        }
        if ($state -match '^Size([0-9]+)$') { $script:SimState.Observation.Mode = 'Full'; $script:SimState.Observation.SizePercent = [int]$Matches[1] }
        elseif ($state -eq 'Reduced') { $script:SimState.Observation.Mode = 'Reduced'; $script:SimState.Observation.SizePercent = 20 }
        elseif ($state -eq 'Full') { $script:SimState.Observation.Mode = 'Full'; $script:SimState.Observation.SizePercent = 40 }
        else { $script:SimState.Observation.Mode = 'Off' }
        "Run ID: $id"
      }
      Mock Restore-RideRun {
        param($RunId,[switch]$WhatIf)
        if ($WhatIf) { return }
        if ($script:SimRecoveryFails) { throw 'simulated recovery failure' }
        if ((ConvertTo-HibernationAcceptanceConfiguration $script:SimState) -cne (ConvertTo-HibernationAcceptanceConfiguration $script:SimSaved[$RunId])) {
          $script:SimCalls.Add('restore')
          $script:SimState = $script:SimSaved[$RunId] | ConvertTo-Json -Depth 5 | ConvertFrom-Json
        }
      }
      Mock Assert-HibernationAcceptanceSnapshot {
        param($RunId,$Before)
        if ((ConvertTo-HibernationAcceptanceConfiguration $script:SimSaved[$RunId]) -cne (ConvertTo-HibernationAcceptanceConfiguration $Before)) { throw 'wrong snapshot' }
      }
      Mock Start-HibernationAcceptanceTrace { 'synthetic handler' }
      Mock Get-HibernationAcceptanceTrace { $script:SimCalls.ToArray() }
      Mock Set-HibernationAcceptanceInterruption { param($Handler,$Enabled) $script:SimInterrupt = $Enabled }
      Mock Stop-HibernationAcceptanceTrace {}
    }
  }
  It 'runs all 18 cases and interrupted recovery while refusing to claim exact or transition acceptance' {
    InModuleScope RIDE.HibernationAcceptance {
      Invoke-RideHibernationAcceptance $script:AcceptanceOperation $script:AcceptanceRoot $script:AcceptanceReport $script:AcceptanceEvidence
      $r = Get-Content $script:AcceptanceEvidence -Raw | ConvertFrom-Json
      $r.Cases.Count | Should -Be 18
      @($r.Cases | Where-Object { -not $_.PreviewPassed -or -not $_.RepeatPassed -or -not $_.RecoveryPassed }).Count | Should -Be 0
      $r.ControlledFailure.Triggered | Should -BeTrue
      $r.ControlledFailure.Intermediate.Observation.SizePercent | Should -Be 40
      $r.ControlledFailure.RecoveryPassed | Should -BeTrue
      $r.LifecyclePassed | Should -BeTrue
      $r.RecoveryPassed | Should -BeTrue
      $r.UnrecoveredRunIds.Count | Should -Be 0
      $r.ExactRecovery | Should -BeFalse
      $r.PowerTransitionPassed | Should -BeFalse
      $r.PromotionReady | Should -BeFalse
      $script:SimState.Observation.SizePercent | Should -Be 75
      Should -Invoke Stop-HibernationAcceptanceTrace -Times 1 -Exactly
    }
  }
  It 'stops before mutation when the original configuration cannot be recovered' {
    InModuleScope RIDE.HibernationAcceptance {
      $script:SimState.Available = $false
      { Invoke-RideHibernationAcceptance $script:AcceptanceOperation $script:AcceptanceRoot $script:AcceptanceReport $script:AcceptanceEvidence } | Should -Throw '*unavailable*'
      Should -Invoke Invoke-RidePlan -Times 0
      Should -Invoke Start-HibernationAcceptanceTrace -Times 0
      (Get-Content $script:AcceptanceEvidence -Raw | ConvertFrom-Json).LifecyclePassed | Should -BeFalse
    }
  }
  It 'fails preflight instead of exhausting the system drive' {
    InModuleScope RIDE.HibernationAcceptance {
      Mock Get-HibernationAcceptancePlatform { @{ FreeBytes = 1; PhysicalMemoryBytes = 1GB } }
      { Invoke-RideHibernationAcceptance $script:AcceptanceOperation $script:AcceptanceRoot $script:AcceptanceReport $script:AcceptanceEvidence } | Should -Throw '*Insufficient*'
      Should -Invoke Invoke-RidePlan -Times 0
    }
  }
  It 'detects a mutating preview and recovers the prepared starting state' {
    InModuleScope RIDE.HibernationAcceptance {
      $script:SimPreviewWrites = $true
      { Invoke-RideHibernationAcceptance $script:AcceptanceOperation $script:AcceptanceRoot $script:AcceptanceReport $script:AcceptanceEvidence } | Should -Throw '*preview*'
      $script:AcceptanceReport.LifecyclePassed | Should -BeFalse
      $script:AcceptanceReport.UnrecoveredRunIds.Count | Should -Be 0
      $script:AcceptanceReport.RecoveryPassed | Should -BeTrue
      $script:SimState.Observation.SizePercent | Should -Be 75
    }
  }
  It 'retains failed-run identity and evidence when recovery fails' {
    InModuleScope RIDE.HibernationAcceptance {
      $script:SimRecoveryFails = $true
      { Invoke-RideHibernationAcceptance $script:AcceptanceOperation $script:AcceptanceRoot $script:AcceptanceReport $script:AcceptanceEvidence } | Should -Throw '*recovery failure*'
      $r = Get-Content $script:AcceptanceEvidence -Raw | ConvertFrom-Json
      $r.RecoveryPassed | Should -BeFalse
      $r.UnrecoveredRunIds.Count | Should -BeGreaterThan 0
      $r.RecoveryError | Should -BeLike '*recovery failure*'
      Should -Invoke Stop-HibernationAcceptanceTrace -Times 1
    }
  }
  It 'does not mistake equal byte allocation for restored configuration or compare dormant Off sizes' {
    InModuleScope RIDE.HibernationAcceptance {
      $a = @{ Observation = @{ Mode = 'Full'; SizePercent = 75; FileBytes = 1 } }
      $b = @{ Observation = @{ Mode = 'Full'; SizePercent = 50; FileBytes = 1 } }
      ConvertTo-HibernationAcceptanceConfiguration $a | Should -Not -Be (ConvertTo-HibernationAcceptanceConfiguration $b)
      $a.Observation.Mode = 'Off'; $b.Observation.Mode = 'Off'
      ConvertTo-HibernationAcceptanceConfiguration $a | Should -Be (ConvertTo-HibernationAcceptanceConfiguration $b)
    }
  }
}

Describe 'Hibernation acceptance entry guard' {
  It 'traces and interrupts a substituted command boundary without invoking powercfg' {
    InModuleScope RIDE.HibernationAcceptance {
      $engine = Get-Module RIDE.Engine
      $handler = & $engine { (Get-Command Set-RideHibernationState).Module }
      $original = & $handler { (Get-Command Invoke-RideHibernationCommand).ScriptBlock }
      $instrumented = $false
      try {
        & $handler {
          $script:FixtureSyntheticCalls = 0
          function script:Invoke-RideHibernationCommand { param([string[]]$Arguments) $script:FixtureSyntheticCalls++ }
        }
        $traceHandler = Start-HibernationAcceptanceTrace (Split-Path -Parent (Split-Path -Parent $engine.Path))
        $instrumented = $true
        Set-HibernationAcceptanceInterruption $traceHandler $true
        { & $handler { Invoke-RideHibernationCommand @('/hibernate','/size','0') } } | Should -Throw '*interruption after successful native size reset*'
        $events = @(Get-HibernationAcceptanceTrace $traceHandler)
        $events.Count | Should -Be 1
        $events[0].NativeCompleted | Should -BeTrue
        $events[0].InjectedInterruption | Should -BeTrue
        (& $handler { $script:FixtureSyntheticCalls }) | Should -Be 1
        Stop-HibernationAcceptanceTrace $traceHandler
        $instrumented = $false
        & $handler { Invoke-RideHibernationCommand @('/hibernate','off') }
        (& $handler { $script:FixtureSyntheticCalls }) | Should -Be 2
      } finally {
        if ($instrumented) { Stop-HibernationAcceptanceTrace $handler }
        & $handler { param($Body) Set-Item Function:script:Invoke-RideHibernationCommand -Value $Body; Remove-Variable FixtureSyntheticCalls -Scope Script -ErrorAction SilentlyContinue } $original
      }
    }
  }
  It 'refuses missing disposable markers before probing the workstation' {
    InModuleScope RIDE.HibernationAcceptance {
      $old = $env:RIDE_TEST_GUEST
      try {
        $env:RIDE_TEST_GUEST = '0'
        Mock Get-CimInstance { throw 'workstation probe must not run' }
        { Assert-RideHibernationAcceptanceGuest @{} 'C:\unused' ('a' * 32) } | Should -Throw '*correlated disposable*'
        Should -Invoke Get-CimInstance -Times 0
      } finally { $env:RIDE_TEST_GUEST = $old }
    }
  }
}
