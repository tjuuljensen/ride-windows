<#
.SYNOPSIS
  Validate catalog-driven package prerequisite planning and removal protection.
.DESCRIPTION
  Exercises dependency ordering, reason reporting, de-duplication and removal
  guards with mocked package state. No installer or Windows package state changes.
.EXAMPLE
  Invoke-Pester .\tests\PackageDependencyPlanning.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  No package, installer, network source or Windows state is changed.
#>
BeforeDiscovery {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.Engine.psm1') -Force
}

Describe 'Catalog-driven package prerequisite planning' {
  InModuleScope RIDE.Engine {
    BeforeEach {
      Mock Get-RideRecordedPackageSelection { $null }
      Mock Get-RidePackagePrerequisiteStatus {
        if ($Operation.Id -eq 'package.imagemagick-portable-q16') {
          [pscustomobject]@{Satisfied=$false;Reason='package.imagemagick-portable-q16 requires vcomp140.dll version 14.50.35710.0 or later';Directory=$null}
        } else {
          [pscustomobject]@{Satisfied=$true;Reason=$null;Directory=$null}
        }
      }
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$false;DisplayVersion=$null} }
    }

    It 'orders an unmet system DLL runtime prerequisite before its consumer and explains why' {
      $plan=@(Get-RideSingleOperationPlan -Id 'package.imagemagick-portable-q16' -Action Install)
      @($plan.Operation.Id) | Should -Be @('package.vcredist-v14-x64','package.imagemagick-portable-q16')
      $plan[0].Reason | Should -Match 'Required by package.imagemagick-portable-q16'
      $plan[1].Reason | Should -BeNullOrEmpty
    }

    It 'keeps the declared runtime visible when the system DLL and version requirement are satisfied' {
      Mock Get-RidePackagePrerequisiteStatus { [pscustomobject]@{Satisfied=$true;Reason=$null;Directory=$null} } -ParameterFilter {$Operation.Id -eq 'package.imagemagick-portable-q16'}
      $plan=@(Get-RideSingleOperationPlan -Id 'package.imagemagick-portable-q16' -Action Install)
      @($plan.Operation.Id) | Should -Be @('package.vcredist-v14-x64','package.imagemagick-portable-q16')
      $plan[0].Reason | Should -Match 'Required by package.imagemagick-portable-q16'
    }

    It 'deduplicates a prerequisite explicitly selected with its consumer' {
      $profile=@{SchemaVersion=1;Name='Runtime and ImageMagick';Operations=@(
        @{Id='package.vcredist-v14-x64';State='Present'},
        @{Id='package.imagemagick-portable-q16';State='Present';Variant='portable'}
      )}
      $plan=@(Get-RidePlan -Profile $profile)
      @($plan.Operation.Id) | Should -Be @('package.vcredist-v14-x64','package.imagemagick-portable-q16')
      @($plan | Where-Object { $_.Operation.Id -eq 'package.vcredist-v14-x64' }).Count | Should -Be 1
      $plan[0].Reason | Should -Match 'Required by package.imagemagick-portable-q16'
    }

    It 'refuses to proceed when a registered prerequisite package does not satisfy its declared requirement' {
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$true;DisplayVersion='14.40.33810.0'} } -ParameterFilter {$Operation.Id -eq 'package.vcredist-v14-x64'}
      { Get-RideSingleOperationPlan -Id 'package.imagemagick-portable-q16' -Action Install } | Should -Throw '*is installed, but does not satisfy*'
    }

    It 'permits an unsupported candidate package only when its declared installed state already satisfies the plan' {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$true;DisplayVersion='4.0.0'} } -ParameterFilter {$Operation.Id -eq 'package.docker-desktop'}
      $item=[pscustomobject]@{Operation=(Get-RideOperation -Id 'package.docker-desktop');State='Present'}
      { & { $WhatIfPreference=$true; Assert-RidePlanAllowed -Plan @($item) } } | Should -Not -Throw
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$false} } -ParameterFilter {$Operation.Id -eq 'package.docker-desktop'}
      { & { $WhatIfPreference=$true; Assert-RidePlanAllowed -Plan @($item) } } | Should -Throw '*does not support Windows 11*'
    }

    It 'rejects a hand-built consumer-only mutation plan before saving state or invoking a handler' {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Save-RideOperationSnapshot { throw 'Must not capture state.' }
      Mock Install-RidePackage { throw 'Must not install.' }
      $consumer=Resolve-RidePackageSelection (Get-RideOperation -Id 'package.imagemagick-portable-q16') -Variant portable -IgnorePreferences
      $plan=@([pscustomobject]@{Operation=$consumer;State='Present'})
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Package prerequisite plan is incomplete or stale*'
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Install-RidePackage -Exactly 0
    }
  }
}

Describe 'Package prerequisite removal protection and ordering' {
  InModuleScope RIDE.Engine {
    BeforeEach {
      Mock Get-RideRecordedPackageSelection { $null }
      Mock Get-RideInstalledPackage {
        [pscustomobject]@{Present=($Operation.Id -eq 'package.imagemagick-portable-q16')}
      }
    }

    It 'refuses to remove a shared prerequisite while an installed dependent remains' {
      $profile=@{SchemaVersion=1;Name='Remove runtime';Operations=@(@{Id='package.vcredist-v14-x64';State='Absent'})}
      { Get-RidePlan -Profile $profile } | Should -Throw '*while dependent package ''package.imagemagick-portable-q16'' is installed*'
    }

    It 'resolves portable install paths before inspecting prerequisite dependents' {
      Mock Get-RidePackageConfiguration -ModuleName RIDE.PackageSelection { @{ToolsDirectory='C:\RIDE-Test-Tools';PackageVariantPreference=$null} }
      $catalog=Get-RideCatalog
      $selection=@(Get-RidePackageDependencySelections -Catalog $catalog | Where-Object Id -eq 'package.imagemagick-portable-q16')
      $selection.Count | Should -Be 1
      $selection[0].ResolvedToolsDirectory | Should -Be 'C:\RIDE-Test-Tools'
      $selection[0].InstallDirectory | Should -Be 'C:\RIDE-Test-Tools\imagemagick-portable-q16'
    }

    It 'removes selected dependents before their prerequisite even when selection order is reversed' {
      $profile=@{SchemaVersion=1;Name='Remove ImageMagick and runtime';Operations=@(
        @{Id='package.vcredist-v14-x64';State='Absent'},
        @{Id='package.imagemagick-portable-q16';State='Absent';Variant='portable'}
      )}
      $plan=@(Get-RidePlan -Profile $profile)
      @($plan.Operation.Id) | Should -Be @('package.imagemagick-portable-q16','package.vcredist-v14-x64')
    }
  }
}
