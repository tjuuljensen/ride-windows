<#
.SYNOPSIS
  Verify persistent user PATH catalog and engine lifecycle boundaries.
.DESCRIPTION
  Uses a synthetic current-user PATH observation and mocked handler boundaries.
  No live registry value is read or changed.
.EXAMPLE
  Invoke-Pester .\tests\UserPathEngine.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Prerequisites: Repository engine; TestDrive. Registry access is mocked.
  Recovery: Pester removes only its own temporary state.
  Version: Repository test fixture; no independent CLI version.
#>

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.UserPathPreparation.psm1') -Force
  $script:UserPathOperation = Get-RideOperation -Id 'windows.user-bin-persistent-path'

  function New-UserPathEngineObservation {
    param([string] $Value = 'C:\Tools', [string] $Kind = 'ExpandString')
    [pscustomobject]@{
      SchemaVersion = 1
      Kind = 'UserPathObservation'
      Status = 'Captured'
      ReadyForMutation = $false
      Context = [pscustomobject]@{
        ComputerName = 'TEST-VM'
        UserSid = 'S-1-5-21-1-2-3-1001'
        SessionId = 1
        UserProfile = 'C:\Users\Fixture'
        NativeProcess = $true
        UserInteractive = $true
      }
      Path = [pscustomobject]@{
        KeyExists = $true
        Exists = $true
        Kind = $Kind
        Value = $Value
      }
    }
  }
}

Describe 'Persistent user PATH engine lifecycle' {
  It 'keeps the operation target-gated and exposes its candidate through status and plan' {
    $script:UserPathOperation.PendingAcceptance | Should -BeTrue
    $script:UserPathOperation.SupportedTargets | Should -BeNullOrEmpty
    $script:UserPathOperation.CandidateTargets | Should -Contain 'Windows 11'

    InModuleScope RIDE.Engine -Parameters @{ Observation = (New-UserPathEngineObservation) } {
      param($Observation)
      Mock Get-RideCurrentUserBinPathObservation { $Observation }
      $operation = Get-RideOperation -Id 'windows.user-bin-persistent-path'
      $state = Get-RideCurrentState -Operation $operation
      $state.Available | Should -BeTrue
      (Get-RideCurrentValueText -Operation $operation -CurrentState $state) | Should -Match 'user-bin entry: Absent'

      $plan = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Enabled)
      $shown = Show-RidePlan $plan | Out-String -Width 4096
      $shown | Should -Match 'Append existing current-user bin to persistent user PATH'
      $shown | Should -Match 'DesiredState\s+: Enabled'
    }
  }

  It 'captures literal prior PATH text, registry kind and entry-owned recovery data' {
    $stateRoot = Join-Path $TestDrive 'state'
    InModuleScope RIDE.Engine -Parameters @{
      Operation = $script:UserPathOperation
      StateRoot = $stateRoot
      Observation = (New-UserPathEngineObservation -Value 'C:\Tools;;C:\Other' -Kind String)
    } {
      param($Operation, $StateRoot, $Observation)
      $script:PathTestStateRoot = $StateRoot
      Mock Initialize-RideStateRoot { $script:PathTestStateRoot }
      Mock Get-RideCurrentUserBinPathObservation { $Observation }
      $current = Get-RideCurrentState -Operation $Operation
      Save-RideOperationSnapshot -RunId 'q08-test-run' -Operation $Operation -CurrentState $current -DesiredState Enabled

      $recordPath = Join-Path $StateRoot 'q08-test-run/windows.user-bin-persistent-path.json'
      $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
      $record.Kind | Should -Be 'UserPath'
      $record.Snapshot.OperationId | Should -BeExactly $Operation.Id
      $record.Snapshot.UserPathSnapshot.Original.Path.Value | Should -BeExactly 'C:\Tools;;C:\Other'
      $record.Snapshot.UserPathSnapshot.Original.Path.Kind | Should -BeExactly 'String'
      $record.Snapshot.UserPathSnapshot.OwnsEntry | Should -BeTrue
      $record.Snapshot.ExpectedValue.Value | Should -BeExactly 'C:\Tools;;C:\Other;C:\Users\Fixture\bin'
    }
  }

  It 'refuses plan execution while Windows acceptance has not added a supported target' {
    $plan = @(Get-RideSingleOperationPlan -Id $script:UserPathOperation.Id -Action Set -State Enabled)
    { Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false } | Should -Throw '*does not support*Windows 11*'
  }

  It 'preflights a saved run and dispatches entry-owned recovery through the guarded helper' {
    $runId = '0123456789abcdef0123456789abcdef'
    $stateRoot = Join-Path $TestDrive 'restore-state'
    $runDirectory = Join-Path $stateRoot $runId
    $null = New-Item -ItemType Directory -Path $runDirectory -Force

    $original = New-UserPathEngineObservation -Value 'C:\Tools' -Kind ExpandString
    $patch = New-RideUserBinPathPatch -Observation $original
    $current = New-UserPathEngineObservation -Value $patch.DesiredValue.Value -Kind ExpandString
    $snapshot = [ordered]@{
      SnapshotVersion = 1
      OperationId = $script:UserPathOperation.Id
      OriginalObservation = $original
      UserPathSnapshot = $patch.Snapshot
      ExpectedValue = $patch.DesiredValue
    }
    $record = [ordered]@{
      SchemaVersion = 1
      RunId = $runId
      OperationId = $script:UserPathOperation.Id
      Kind = 'UserPath'
      Scope = 'User'
      Snapshot = $snapshot
      CreatedUtc = [DateTime]::UtcNow.ToString('o')
    }
    $record | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runDirectory 'windows.user-bin-persistent-path.json') -Encoding UTF8
    [ordered]@{SchemaVersion=1;RunId=$runId;Scopes=@('User');OperationIds=@($script:UserPathOperation.Id);CreatedUtc=[DateTime]::UtcNow.ToString('o')} |
      ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $runDirectory '_manifest.json') -Encoding UTF8

    $restorableOperation = $script:UserPathOperation.Clone()
    $restorableOperation.SupportedTargets = @('Windows 11')
    InModuleScope RIDE.Engine -Parameters @{
      Operation = $restorableOperation
      StateRoot = $stateRoot
      CurrentState = [pscustomobject]@{Available=$true;Observation=$current}
      RunId = $runId
    } {
      param($Operation, $StateRoot, $CurrentState, $RunId)
      $script:PathRestoreCatalog = @{SchemaVersion=1;Operations=@($Operation);Groups=@()}
      $script:PathRestoreStateRoot = $StateRoot
      Mock Get-RideCatalog { $script:PathRestoreCatalog }
      Mock Get-RideStateRoot { $script:PathRestoreStateRoot }
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $false }
      Mock Get-RideCurrentState { $CurrentState }
      Mock Set-RideUserBinPathRecovery {
        [pscustomobject]@{Applied=$true;Changed=$true;EffectivePathVerified=$false;EnvironmentBroadcast=$false}
      }

      $result = @(Restore-RideRun -RunId $RunId -Confirm:$false)
      $result | Should -Contain "Restored prior state: $($Operation.Id)"
      Should -Invoke Get-RideCurrentState -Times 2 -Exactly
      Should -Invoke Set-RideUserBinPathRecovery -Times 1 -Exactly -ParameterFilter {
        $Snapshot.OwnsEntry -and $Snapshot.Entry -ceq 'C:\Users\Fixture\bin'
      }
    }
  }
}
