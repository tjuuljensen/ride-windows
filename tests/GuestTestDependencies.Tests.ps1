<#
.SYNOPSIS
  Test setup of exact guest-only PowerShell test dependencies.

.DESCRIPTION
  Mocks PowerShellGet and module discovery. Does not access the network or modify the machine.

.EXAMPLE
  Invoke-Pester .\tests\GuestTestDependencies.Tests.ps1

.INPUTS
  None.

.OUTPUTS
  Pester test results.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Pester 5.x.
  Recovery: Pester mock teardown; no system changes.
  Version: Test fixture.
#>

BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot 'integration\RIDE.GuestTestDependencies.psm1') -Force
}

Describe 'Guest test dependency setup' {
  InModuleScope RIDE.GuestTestDependencies {
    BeforeEach {
      Mock Install-PackageProvider { }
      Mock Install-Module { }
    }

    It 'uses an already installed Pester 5.7.1 without package acquisition' {
      Mock Get-Module {
        @(
          [pscustomobject]@{ Version = [version]'6.2.0'; ModuleBase = 'C:\Modules\Pester\6.2.0' }
          [pscustomobject]@{ Version = [version]'5.7.1'; ModuleBase = 'C:\Modules\Pester\5.7.1' }
        )
      }

      $result = Install-RideGuestPester

      $result.Action | Should -BeExactly 'AlreadyPresent'
      $result.Version | Should -BeExactly '5.7.1'
      $result.ModuleBase | Should -BeExactly 'C:\Modules\Pester\5.7.1'
      Should -Invoke Install-PackageProvider -Times 0 -Exactly
      Should -Invoke Install-Module -Times 0 -Exactly
    }

    It 'installs the exact pinned version for the current guest user when absent' {
      $script:moduleLookups = 0
      Mock Get-Module {
        $script:moduleLookups++
        if ($script:moduleLookups -eq 1) { return }
        [pscustomobject]@{ Version = [version]'5.7.1'; ModuleBase = 'C:\Users\admin\Documents\WindowsPowerShell\Modules\Pester\5.7.1' }
      }

      $result = Install-RideGuestPester

      $result.Action | Should -BeExactly 'Installed'
      $result.Version | Should -BeExactly '5.7.1'
      Should -Invoke Install-PackageProvider -Times 1 -Exactly -ParameterFilter { $Name -eq 'NuGet' -and $Scope -eq 'CurrentUser' }
      Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter { $Name -eq 'Pester' -and $RequiredVersion -eq '5.7.1' -and $Repository -eq 'PSGallery' -and $Scope -eq 'CurrentUser' -and $SkipPublisherCheck -and $Force }
    }

    It 'fails when PowerShell Gallery does not supply the pinned version' {
      Mock Get-Module { }

      { Install-RideGuestPester } | Should -Throw '*unavailable after the guest dependency setup*'
      Should -Invoke Install-Module -Times 1 -Exactly
    }
  }
}
