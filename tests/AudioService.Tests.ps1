<#
.SYNOPSIS
  Verify Windows Audio primary-service ownership and dependency refusal.
.DESCRIPTION
  Service, CIM, registry and native SCM reads/writes are mocked. No actual audio,
  device, session, service, package or disposable VM is changed.
.EXAMPLE
  Invoke-Pester ./tests/AudioService.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Add guarded Audiosrv lifecycle and no-dependency ownership.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
}
Describe 'Windows Audio service' {
  BeforeEach {
    $op = Get-RideOperation windows.audio-service
    InModuleScope RIDE-Services -Parameters @{ Op = $op } {
      param($Op)
      $script:AudioOp = $Op
      $script:AudioState = @{ Startup = 'Manual'; Status = 'Stopped'; Delay = $false }
      $script:AudioRequired = @([pscustomobject]@{ ServiceName = 'AudioEndpointBuilder'; Status = 'Running' }, [pscustomobject]@{ ServiceName = 'RpcSs'; Status = 'Running' })
      $script:AudioDependents = @([pscustomobject]@{ ServiceName = 'FixtureAudioClient'; Status = 'Stopped' })
      $script:AudioGroups = @()
      $script:AudioRaw = [pscustomobject]@{ KeyExisted = $true; Exists = $false; Value = $null; ValueType = $null }
      Mock Get-Service { [pscustomobject]@{ ServiceName = 'Audiosrv'; Status = $script:AudioState.Status; ServicesDependedOn = $script:AudioRequired; DependentServices = $script:AudioDependents } }
      Mock Get-CimInstance { [pscustomobject]@{ StartMode = $(if ($script:AudioState.Startup -eq 'Automatic') { 'Auto' } else { $script:AudioState.Startup }) } }
      Mock Get-RideServiceDelayedAutoStart { $script:AudioState.Delay }
      Mock Set-RideServiceDelayedAutoStart { $script:AudioState.Delay = $Delayed }
      Mock Get-RideSettingState {
        if ($Operation.ValueName -eq 'DependOnGroup') { return [pscustomobject]@{ Exists = [bool]$script:AudioGroups.Count; Value = $script:AudioGroups; ValueType = 'MultiString'; KeyExisted = $true } }
        $script:AudioRaw
      }
      Mock Restore-RideSettingState { $script:AudioRaw = $Snapshot }
      Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like 'HKLM:*' }
      Mock Set-Service { $script:AudioState.Startup = [string]$StartupType }
      Mock Start-Service { $script:AudioState.Status = 'Running' }
      Mock Stop-Service { $script:AudioState.Status = 'Stopped' }
      Mock Resume-Service { $script:AudioState.Status = 'Running' }
      Mock Suspend-Service { $script:AudioState.Status = 'Paused' }
    }
  }
  It 'captures dependency observations without any changes and retains primary version-2 recovery' {
    InModuleScope RIDE-Services {
      $before = Get-RideWindowsServiceState $script:AudioOp
      $before.ServiceName | Should -Be 'Audiosrv'
      $before.SnapshotVersion | Should -Be 2
      $before.Dependencies.Entries.Count | Should -Be 3
      $before.DelayedAutoStart.Exists | Should -BeFalse
      Should -Invoke Set-Service -Times 0
      Should -Invoke Start-Service -Times 0
      Should -Invoke Stop-Service -Times 0
    }
  }
  It 'starts only Audiosrv when prerequisites already run and repeats without further mutation' {
    InModuleScope RIDE-Services {
      Set-RideWindowsServiceState $script:AudioOp AutomaticRunning
      Set-RideWindowsServiceState $script:AudioOp AutomaticRunning
      Should -Invoke Start-Service -Times 1 -Exactly -ParameterFilter { $Name -eq 'Audiosrv' }
      Should -Invoke Set-Service -Times 1 -Exactly -ParameterFilter { $Name -eq 'Audiosrv' -and [string]$StartupType -eq 'Automatic' }
      $script:AudioRequired.Status | Should -Be @('Running', 'Running')
      $script:AudioDependents.Status | Should -Be @('Stopped')
    }
  }
  It 'stops only the primary service and uses Manual rather than Disabled or Force' {
    InModuleScope RIDE-Services {
      $script:AudioState.Startup = 'Automatic'; $script:AudioState.Status = 'Running'
      Set-RideWindowsServiceState $script:AudioOp ManualStopped
      $script:AudioState.Startup | Should -Be 'Manual'
      Should -Invoke Stop-Service -Times 1 -Exactly -ParameterFilter { $Name -eq 'Audiosrv' -and -not $Force }
      Should -Invoke Set-Service -Times 0 -ParameterFilter { $Name -ne 'Audiosrv' -or [string]$StartupType -eq 'Disabled' }
    }
  }
  It 'refuses a stopped prerequisite before changing startup configuration' {
    InModuleScope RIDE-Services {
      $script:AudioRequired[0].Status = 'Stopped'
      { Set-RideWindowsServiceState $script:AudioOp AutomaticRunning } | Should -Throw '*refusing implicit dependency start*'
      Should -Invoke Set-Service -Times 0
      Should -Invoke Start-Service -Times 0
    }
  }
  It 'refuses active dependent services before changing startup configuration' {
    InModuleScope RIDE-Services {
      $script:AudioState.Startup = 'Automatic'; $script:AudioState.Status = 'Running'
      $script:AudioDependents[0].Status = 'Running'
      { Set-RideWindowsServiceState $script:AudioOp ManualStopped } | Should -Throw '*Dependent services are active*'
      Should -Invoke Set-Service -Times 0
      Should -Invoke Stop-Service -Times 0
    }
  }
  It 'refuses load-order group dependency ambiguity before writes' {
    InModuleScope RIDE-Services {
      $script:AudioGroups = @('FixtureGroup')
      { Set-RideWindowsServiceState $script:AudioOp AutomaticRunning } | Should -Throw '*load-order group dependencies*'
      Should -Invoke Set-Service -Times 0
      Should -Invoke Start-Service -Times 0
    }
  }
  It 'refuses transitional or missing dependency inspection instead of treating it as empty' {
    InModuleScope RIDE-Services {
      $script:AudioRequired[0].Status = 'StartPending'
      { Set-RideWindowsServiceState $script:AudioOp AutomaticRunning } | Should -Throw '*unknown or transitional*'
      $script:AudioRequired[0].Status = 'Running'
      Mock Get-Service { [pscustomobject]@{ Status = 'Stopped' } }
      { Set-RideWindowsServiceState $script:AudioOp AutomaticRunning } | Should -Throw '*inspection is unavailable*'
      Should -Invoke Set-Service -Times 0
    }
  }
  It 'rechecks dependencies after configuration and refuses a newly unsafe runtime transition' {
    InModuleScope RIDE-Services {
      Mock Set-Service { $script:AudioState.Startup = [string]$StartupType; $script:AudioRequired[0].Status = 'Stopped' }
      { Set-RideWindowsServiceState $script:AudioOp AutomaticRunning } | Should -Throw '*failed during runtime*refusing implicit dependency start*'
      Should -Invoke Start-Service -Times 0
    }
  }
  It 'avoids a redundant start when a trigger starts the primary after configuration' {
    InModuleScope RIDE-Services {
      Mock Set-Service { $script:AudioState.Startup = [string]$StartupType; $script:AudioState.Status = 'Running' }
      Set-RideWindowsServiceState $script:AudioOp AutomaticRunning
      Should -Invoke Start-Service -Times 0
      $script:AudioState.Status | Should -Be 'Running'
    }
  }
  It 'reports post-transition dependency drift without attempting dependent recovery' {
    InModuleScope RIDE-Services {
      Mock Start-Service { $script:AudioState.Status = 'Running'; $script:AudioDependents[0].Status = 'Running' }
      { Set-RideWindowsServiceState $script:AudioOp AutomaticRunning } | Should -Throw '*failed during verification*dependency state changed*'
      Should -Invoke Stop-Service -Times 0
      Should -Invoke Set-Service -Times 0 -ParameterFilter { $Name -ne 'Audiosrv' }
    }
  }
  It 'recovers exact primary configuration/runtime/delay without adopting dependent services' {
    InModuleScope RIDE-Services {
      $before = Get-RideWindowsServiceState $script:AudioOp
      Set-RideWindowsServiceState $script:AudioOp AutomaticRunning
      Restore-RideWindowsServiceState $script:AudioOp ($before | ConvertTo-Json -Depth 6 | ConvertFrom-Json)
      $after = Get-RideWindowsServiceState $script:AudioOp
      $after.StartupType | Should -Be 'Manual'
      $after.Status | Should -Be 'Stopped'
      $after.DelayedAutoStart.Exists | Should -BeFalse
      (ConvertTo-RideServiceDependencyText $after.Dependencies) | Should -Be (ConvertTo-RideServiceDependencyText $before.Dependencies)
      Should -Invoke Stop-Service -Times 0 -ParameterFilter { $Name -ne 'Audiosrv' }
    }
  }
  It 'keeps a changed active dependent as a recovery conflict rather than force-stopping it' {
    InModuleScope RIDE-Services {
      $before = Get-RideWindowsServiceState $script:AudioOp
      Set-RideWindowsServiceState $script:AudioOp AutomaticRunning
      $script:AudioDependents[0].Status = 'Running'
      { Restore-RideWindowsServiceState $script:AudioOp $before } | Should -Throw '*Dependent services are active*'
      Should -Invoke Stop-Service -Times 0
      Should -Invoke Set-Service -Times 1 -Exactly
    }
  }
  It 'blocks the candidate before service inspection and completes only its declared choices' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.audio-service -State man"
    @([Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches.CompletionText) | Should -Be @('ManualStopped')
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideCurrentState { throw 'must not inspect candidate service' }
      $op = Get-RideOperation windows.audio-service
      $op.SupportedTargets.Count | Should -Be 0
      $op.States.Keys.Count | Should -Be 2
      { Invoke-RidePlan -Plan @([pscustomobject]@{ Operation = $op; State = 'AutomaticRunning' }) -WhatIf -Confirm:$false } | Should -Throw '*does not support*'
      Should -Invoke Get-RideCurrentState -Times 0
    }
    @(Get-RideCatalogValidationErrors (Get-RideCatalog)).Count | Should -Be 0
  }
}
