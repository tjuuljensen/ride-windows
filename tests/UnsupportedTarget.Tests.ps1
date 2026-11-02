<#
.SYNOPSIS
  Verify explicit target exploration and saved audit without Windows changes.
.DESCRIPTION
  Uses synthetic target observations, mocked handlers and TestDrive state only.
.EXAMPLE
  Invoke-Pester ./tests/UnsupportedTarget.Tests.ps1
.NOTES
  Windows PowerShell 5.1/PowerShell 7 and Pester 5. Version: 0.1.0.
  Changelog: 0.1.0: Cover opt-in, candidate separation, preview, privilege and audit.
#>
BeforeAll { Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force }
Describe 'Explicit unsupported target exploration' {
  BeforeEach {
    InModuleScope RIDE.Engine -Parameters @{Root=$TestDrive} {
      $script:ExplorationRoot=$Root
      $script:ExplorationOp=(Get-RideOperation windows.show-known-extensions).Clone()
      $script:ExplorationOp.SupportedTargets=@('Windows 11')
      $script:ExplorationOp.MinimumBuild=22000
      $script:ExplorationOp.PendingAcceptance=$false
      $script:ExplorationPlan=@([pscustomobject]@{Operation=$script:ExplorationOp;State='Enabled'})
      Mock Get-RidePlatform {'Unsupported Windows target: Windows 10 build 19045'}
      Mock Get-ItemProperty {[pscustomobject]@{CurrentBuildNumber='19045';ProductName='Windows 10';EditionID='Professional';InstallationType='Client';UBR=1;ProductType='WinNT'}}
      Mock Test-RideAdministrator {$true}
      Mock Get-RideCurrentState {[pscustomobject]@{Exists=$false;Value=$null}}
      Mock Test-RideDesiredState {$false}
      Mock Set-RideSettingState {}
      Mock Restore-RideSettingState {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideRunOperationProgress {}
      Mock Get-RideStateRoot {$script:ExplorationRoot}
      Mock Initialize-RideStateRoot {$script:ExplorationRoot}
    }
  }
  It 'requires the separate switch and never changes catalog support metadata' {
    InModuleScope RIDE.Engine {
      {Invoke-RidePlan $script:ExplorationPlan -AllowCandidate -Confirm:$false} | Should -Throw '*does not support*'
      Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -Confirm:$false | Out-Null
      $script:ExplorationOp.SupportedTargets | Should -Be @('Windows 11')
      Should -Invoke Set-RideSettingState -Exactly 1
    }
  }
  It 'requires candidate opt-in independently' {
    InModuleScope RIDE.Engine {
      $script:ExplorationOp.PendingAcceptance=$true
      {Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -Confirm:$false} | Should -Throw '*also requires -AllowCandidate*'
      Should -Invoke Set-RideSettingState -Exactly 0
      Invoke-RidePlan $script:ExplorationPlan -AllowCandidate -AllowUnsupportedTarget -Confirm:$false | Out-Null
      Should -Invoke Set-RideSettingState -Exactly 1
    }
  }
  It 'previews unsupported candidates without writes or mutation' {
    InModuleScope RIDE.Engine {
      $script:ExplorationOp.PendingAcceptance=$true
      Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -WhatIf | Out-Null
      Should -Invoke Set-RideSettingState -Exactly 0
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Initialize-RideStateRoot -Exactly 0
    }
  }
  It 'keeps elevation and user-context restrictions' {
    InModuleScope RIDE.Engine {
      $script:ExplorationOp.RequiresAdmin=$true
      Mock Test-RideAdministrator {$false}
      {Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -Confirm:$false} | Should -Throw '*elevated PowerShell*'
      $script:ExplorationOp.RequiresAdmin=$false;$script:ExplorationOp.RequiresUnelevatedUser=$true
      Mock Test-RideAdministrator {$true}
      {Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -Confirm:$false} | Should -Throw '*non-elevated PowerShell*'
      Should -Invoke Set-RideSettingState -Exactly 0
    }
  }
  It 'keeps whole-plan dependency and handler failures' {
    InModuleScope RIDE.Engine {
      Mock Expand-RidePackageDependencyPlan {@($script:ExplorationPlan[0],[pscustomobject]@{Operation=@{Id='extra'};State='Present'})}
      {Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -Confirm:$false} | Should -Throw '*prerequisite plan is incomplete*'
      Should -Invoke Initialize-RideStateRoot -Exactly 0
      Mock Expand-RidePackageDependencyPlan {$script:ExplorationPlan}
      Mock Set-RideSettingState {throw 'Synthetic handler integrity refusal'}
      {Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -Confirm:$false} | Should -Throw '*Synthetic handler integrity refusal*'
    }
  }
  It 'persists actual target and overridden restrictions before a changed run' {
    InModuleScope RIDE.Engine {
      Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -Confirm:$false | Out-Null
      $file=Get-ChildItem -LiteralPath $script:ExplorationRoot -Filter _manifest.json -Recurse | Select-Object -First 1
      $audit=(Get-Content -LiteralPath $file.FullName -Raw|ConvertFrom-Json).TargetExploration[0]
      $audit.Unsupported | Should -BeTrue
      $audit.Build | Should -Be 19045
      $audit.EditionId | Should -Be Professional
      $audit.OverriddenRestrictions | Should -Contain 'BelowMinimumBuild'
      $audit.OverriddenRestrictions | Should -Contain 'UndeclaredSupportedTarget'
    }
  }
  It 'requires fresh restore opt-in and audits only an approved restore' {
    InModuleScope RIDE.Engine {
      $id='a'*32;$dir=Join-Path $script:ExplorationRoot $id;$null=New-Item -ItemType Directory -Path $dir
      @{SchemaVersion=1;RunId=$id;OperationId=$script:ExplorationOp.Id;Kind='RegistryValue';Scope='User';Snapshot=@{Exists=$false}}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $dir 'fixture.json')
      Mock Get-RideCatalog {@{Operations=@($script:ExplorationOp)}}
      Mock Test-RideAdministrator {$false}
      {Restore-RideRun -RunId $id -Confirm:$false} | Should -Throw '*does not support*'
      Restore-RideRun -RunId $id -AllowUnsupportedTarget -WhatIf | Out-Null
      @(Get-ChildItem -LiteralPath $dir -Filter '*.log' -Force).Count | Should -Be 0
      Should -Invoke Restore-RideSettingState -Exactly 0
      Restore-RideRun -RunId $id -AllowUnsupportedTarget -Confirm:$false | Out-Null
      $logs=@(Get-ChildItem -LiteralPath $dir -Filter '*.log' -Force)
      $logs.Count | Should -Be 1
      (Get-Content -LiteralPath $logs[0].FullName -Raw|ConvertFrom-Json).Action | Should -Be Restore
      Should -Invoke Restore-RideSettingState -Exactly 1
      {Restore-RideRun -RunId $id -Confirm:$false} | Should -Throw '*does not support*'
    }
  }
  It 'records a Desktop Experience restriction even when the OS target is declared' {
    InModuleScope RIDE.Engine {
      $script:ExplorationOp.SupportedTargets=@('Windows Server 2025')
      $script:ExplorationOp.RequiresDesktopExperience=$true
      Mock Get-RidePlatform {'Windows Server 2025'}
      Mock Get-ItemProperty {[pscustomobject]@{CurrentBuildNumber='26100';ProductName='Windows Server';EditionID='ServerStandard';InstallationType='Server Core';UBR=1;ProductType='ServerNT'}}
      {Invoke-RidePlan $script:ExplorationPlan -Confirm:$false} | Should -Throw '*Desktop Experience*'
      $audit=New-RideTargetExplorationRecord -Operation $script:ExplorationOp -Action Apply
      $audit.OverriddenRestrictions | Should -Be @('DesktopExperienceUnavailable')
      Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -WhatIf | Out-Null
      Should -Invoke Set-RideSettingState -Exactly 0
    }
  }
  It 'refuses a mutation when durable target audit cannot be written' {
    InModuleScope RIDE.Engine {
      Mock Write-RideRunManifestAtomically {throw 'Synthetic audit write failure'}
      {Invoke-RidePlan $script:ExplorationPlan -AllowUnsupportedTarget -Confirm:$false} | Should -Throw '*Synthetic audit write failure*'
      Should -Invoke Set-RideSettingState -Exactly 0
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
    }
  }
}
