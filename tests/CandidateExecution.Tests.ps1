<#
.SYNOPSIS
  Verify explicit candidate execution gates without changing Windows.
.DESCRIPTION
  Mocks platform, privilege, live observation and handlers. Previews create no
  saved state. Candidate opt-in does not widen targets or bypass build checks.
.EXAMPLE
  Invoke-Pester ./tests/CandidateExecution.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Version: repository test fixture. Changelog: 2026-11-01: Add candidate gate coverage.
#>
BeforeAll { Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force }

Describe 'Explicit candidate execution' {
  BeforeEach {
    InModuleScope RIDE.Engine {
      $script:CandidateOp = (Get-RideOperation windows.hibernation).Clone()
      $script:CandidatePlan = @([pscustomobject]@{ Operation = $script:CandidateOp; State = 'Reduced' })
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideCurrentState { [pscustomobject]@{ Available = $true; Observation = [pscustomobject]@{ Mode = 'Full'; SizePercent = 75; FileBytes = 1024L; HibernateAvailable = $true } } }
      Mock Set-RideHibernationState { throw 'Native changes must not run in gate tests.' }
      Mock Initialize-RideStateRoot { throw 'Gate tests must not create state.' }
    }
  }

  It 'previews a declared candidate without opt-in and still requires opt-in for a real change' {
    InModuleScope RIDE.Engine {
      $warnings = @()
      Invoke-RidePlan $script:CandidatePlan -WhatIf -WarningVariable warnings | Out-Null
      ($warnings -join ' ') | Should -Match 'acceptance remains pending'
      Should -Invoke Get-RideCurrentState -Times 1
      Should -Invoke Set-RideHibernationState -Times 0
      Should -Invoke Initialize-RideStateRoot -Times 0
      { Invoke-RidePlan $script:CandidatePlan -AllowCandidate:$false -Confirm:$false } | Should -Throw '*acceptance is pending*'
      Should -Invoke Get-RideCurrentState -Times 1
      Should -Invoke Set-RideHibernationState -Times 0
      Should -Invoke Initialize-RideStateRoot -Times 0
    }
  }
  It 'previews a declared candidate without native changes or state creation' {
    InModuleScope RIDE.Engine {
      $warnings = @()
      Invoke-RidePlan $script:CandidatePlan -AllowCandidate -WhatIf -WarningVariable warnings | Out-Null
      ($warnings -join ' ') | Should -Match 'acceptance remains pending'
      Should -Invoke Get-RideCurrentState -Times 1
      Should -Invoke Set-RideHibernationState -Times 0
      Should -Invoke Initialize-RideStateRoot -Times 0
      $script:CandidateOp.SupportedTargets.Count | Should -Be 0
      $script:CandidateOp.PendingAcceptance | Should -BeTrue
    }
  }
  It 'honors inherited preview while retaining explicit candidate opt-in' {
    InModuleScope RIDE.Engine {
      & { $WhatIfPreference = $true; Invoke-RidePlan $script:CandidatePlan -AllowCandidate | Out-Null }
      Should -Invoke Set-RideHibernationState -Times 0
      Should -Invoke Initialize-RideStateRoot -Times 0
    }
  }
  It 'does not allow an undeclared target even with preview and opt-in' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows Server 2025' }
      { Invoke-RidePlan $script:CandidatePlan -AllowCandidate -WhatIf } | Should -Throw '*does not support Windows Server 2025*cannot bypass*'
      Should -Invoke Get-RideCurrentState -Times 0
    }
  }
  It 'requires both pending status and explicit candidate target metadata' {
    InModuleScope RIDE.Engine {
      $script:CandidateOp.PendingAcceptance = $false
      { Assert-RidePlanAllowed $script:CandidatePlan -AllowCandidate } | Should -Throw '*does not support*'
      $script:CandidateOp.PendingAcceptance = $true
      $script:CandidateOp.CandidateTargets = @()
      { Assert-RidePlanAllowed $script:CandidatePlan -AllowCandidate } | Should -Throw '*Candidate targets: <none>*'
    }
  }
  It 'keeps accepted target behavior without requiring opt-in' {
    InModuleScope RIDE.Engine {
      $script:CandidateOp.SupportedTargets = @('Windows 11')
      $script:CandidateOp.PendingAcceptance = $false
      { Assert-RidePlanAllowed $script:CandidatePlan } | Should -Not -Throw
    }
  }
  It 'permits an already installed package no-op outside its declared target without widening support' {
    InModuleScope RIDE.Engine {
      $package = (Get-RideOperation -Id 'package.7zip').Clone()
      $package.SupportedTargets = @()
      $package.PendingAcceptance = $false
      Mock Get-RideInstalledPackage { [pscustomobject]@{ Present = $true } }
      $plan = @([pscustomobject]@{ Operation = $package; State = 'Present' })
      { Assert-RidePlanAllowed -Plan $plan } | Should -Not -Throw
      Should -Invoke Get-RideInstalledPackage -Times 1
      $package.SupportedTargets.Count | Should -Be 0
      $package.PendingAcceptance | Should -BeFalse
    }
  }
  It 'does not permit an uninstalled package on an undeclared target' {
    InModuleScope RIDE.Engine {
      $package = (Get-RideOperation -Id 'package.7zip').Clone()
      $package.SupportedTargets = @()
      $package.PendingAcceptance = $false
      Mock Get-RideInstalledPackage { [pscustomobject]@{ Present = $false } }
      $plan = @([pscustomobject]@{ Operation = $package; State = 'Present' })
      { Assert-RidePlanAllowed -Plan $plan } | Should -Throw '*does not support Windows 11*'
      Should -Invoke Get-RideInstalledPackage -Times 1
    }
  }
  It 'still enforces machine elevation for actual changes' {
    InModuleScope RIDE.Engine {
      Mock Test-RideAdministrator { $false }
      { Invoke-RidePlan $script:CandidatePlan -AllowCandidate -Confirm:$false } | Should -Throw '*elevated PowerShell*'
      Should -Invoke Get-RideCurrentState -Times 0
      Invoke-RidePlan $script:CandidatePlan -AllowCandidate -WhatIf | Out-Null
      Should -Invoke Set-RideHibernationState -Times 0
    }
  }
  It 'still refuses elevation for operations requiring the unelevated user' {
    InModuleScope RIDE.Engine {
      $script:CandidateOp.RequiresAdmin = $false
      $script:CandidateOp.RequiresUnelevatedUser = $true
      { Invoke-RidePlan $script:CandidatePlan -AllowCandidate -Confirm:$false } | Should -Throw '*non-elevated PowerShell*'
      Should -Invoke Get-RideCurrentState -Times 0
    }
  }
  It 'does not bypass a minimum build during preview' {
    InModuleScope RIDE.Engine {
      $script:CandidateOp.MinimumBuild = 99999
      Mock Get-ItemProperty { @{ CurrentBuildNumber = '26100' } }
      { Invoke-RidePlan $script:CandidatePlan -AllowCandidate -WhatIf } | Should -Throw '*requires Windows build 99999*'
      Should -Invoke Get-RideCurrentState -Times 0
    }
  }
  It 'does not bypass the Server Desktop Experience requirement' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows Server 2025' }
      Mock Get-ItemProperty { @{ InstallationType = 'Server Core' } }
      $script:CandidateOp.CandidateTargets = @('Windows Server 2025')
      $script:CandidateOp.RequiresDesktopExperience = $true
      { Invoke-RidePlan $script:CandidatePlan -AllowCandidate -WhatIf } | Should -Throw '*Desktop Experience*'
      Should -Invoke Get-RideCurrentState -Times 0
    }
  }
  It 'preflights every profile member before inspecting or changing any member' {
    InModuleScope RIDE.Engine {
      $bad = $script:CandidateOp.Clone(); $bad.Id = 'fixture.undeclared'; $bad.CandidateTargets = @()
      $plan = @($script:CandidatePlan[0], [pscustomobject]@{ Operation = $bad; State = 'Reduced' })
      { Invoke-RidePlan $plan -AllowCandidate -Confirm:$false } | Should -Throw '*fixture.undeclared*does not support*'
      Should -Invoke Get-RideCurrentState -Times 0
      Should -Invoke Initialize-RideStateRoot -Times 0
    }
  }
}
