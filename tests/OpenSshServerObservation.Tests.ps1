<#
.SYNOPSIS
  Verify the read-only OpenSSH Server observation candidate.
.DESCRIPTION
  Mocks all platform, servicing, service, firewall and filesystem sources. No Windows
  component, service, firewall rule, host key or configuration is changed.
.EXAMPLE
  Invoke-Pester .\tests\OpenSshServerObservation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Native OpenSSH Server acceptance is separate and remains pending.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.OpenSshServerObservation.psm1') -Force
}

Describe 'Read-only OpenSSH Server observation candidate' {
  BeforeEach {
    $global:RideSshCapabilityCalls = 0
    $global:RideSshServiceCalls = 0
    $global:RideSshFirewallCalls = 0
    $global:RideSshDataCalls = 0
    Mock Get-RideOpenSshServerPlatformContext -ModuleName RIDE.OpenSshServerObservation {
      [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=123;InstallationType='Client';ProductType='WinNT';NativeProcess=$true}
    }
    Mock Get-RideOpenSshServerCapabilityState -ModuleName RIDE.OpenSshServerObservation {
      $global:RideSshCapabilityCalls++
      [pscustomobject]@{Status='Captured';Name='OpenSSH.Server~~~~0.0.1.0';State='NotPresent'}
    }
    Mock Get-RideOpenSshServerServiceState -ModuleName RIDE.OpenSshServerObservation {
      $global:RideSshServiceCalls++
      [pscustomobject]@{Status='Captured';Name='sshd';State='Stopped';StartMode='Manual';StartName='LocalSystem'}
    }
    Mock Get-RideOpenSshServerFirewallState -ModuleName RIDE.OpenSshServerObservation {
      $global:RideSshFirewallCalls++
      [pscustomobject]@{Status='Captured';Name='OpenSSH-Server-In-TCP';Enabled='False';Direction='Inbound';Action='Allow';Profile='Any';Protocol='TCP';LocalPort='22';PolicyStoreSourceType='Local';PolicyStoreSource='PersistentStore'}
    }
    Mock Get-RideOpenSshServerDataState -ModuleName RIDE.OpenSshServerObservation {
      $global:RideSshDataCalls++
      [pscustomobject]@{Status='Captured';Root='C:\ProgramData\ssh';Files=@([pscustomobject]@{Name='sshd_config';Length=1800;LastWriteTimeUtc='2026-10-24T00:00:00.0000000Z';Sha256=('a'*64);PrivateHostKey=$false});TotalBytes=1800}
    }
  }

  It 'records the four state surfaces separately and remains non-mutation-ready' {
    $result = Get-RideOpenSshServerState -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional
    $result.Kind | Should -BeExactly 'OpenSshServerObservation'
    $result.ReadyForMutation | Should -BeFalse
    $result.RecoverySupported | Should -BeFalse
    @($result.Providers).Name | Should -Be @('Capability','Service','Firewall','ServerData')
    ($result.Providers | Where-Object Name -eq Service).Observation.StartMode | Should -BeExactly 'Manual'
    ($result.Providers | Where-Object Name -eq Firewall).Observation.LocalPort | Should -BeExactly '22'
    ($result.Providers | Where-Object Name -eq ServerData).Observation.Files[0].Name | Should -BeExactly 'sshd_config'
  }

  It 'refuses a mismatched target before querying component state' {
    { Get-RideOpenSshServerState -ExpectedComputerName OTHER-VM -ExpectedBuild 26100 -ExpectedEditionId Professional } | Should -Throw '*target differs*'
    $global:RideSshCapabilityCalls | Should -Be 0
    $global:RideSshServiceCalls | Should -Be 0
    $global:RideSshFirewallCalls | Should -Be 0
    $global:RideSshDataCalls | Should -Be 0
  }

  It 'reports provider failures as unavailable instead of absence' {
    Mock Get-RideOpenSshServerFirewallState -ModuleName RIDE.OpenSshServerObservation { throw 'Access denied' }
    $result = Get-RideOpenSshServerState -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional
    $firewall = $result.Providers | Where-Object Name -eq Firewall
    $firewall.Status | Should -BeExactly 'Unavailable'
    $firewall.Observation | Should -BeNullOrEmpty
    $firewall.ErrorType | Should -BeExactly 'System.Management.Automation.RuntimeException'
    $result.ReadyForMutation | Should -BeFalse
  }

  It 'does not imply service activation from a present capability' {
    Mock Get-RideOpenSshServerCapabilityState -ModuleName RIDE.OpenSshServerObservation {
      [pscustomobject]@{Status='Captured';Name='OpenSSH.Server~~~~0.0.1.0';State='Installed'}
    }
    $result = Get-RideOpenSshServerState -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional
    ($result.Providers | Where-Object Name -eq Capability).Observation.State | Should -BeExactly 'Installed'
    ($result.Providers | Where-Object Name -eq Service).Observation.State | Should -BeExactly 'Stopped'
    ($result.Providers | Where-Object Name -eq Firewall).Observation.Enabled | Should -BeExactly 'False'
  }
}

Describe 'OpenSSH Server observation provider boundaries' {
  It 'selects only the exact OpenSSH Server capability identity' {
    InModuleScope RIDE.OpenSshServerObservation {
      Mock 'Dism\Get-WindowsCapability' {
        @(
          [pscustomobject]@{Name='OpenSSH.Client~~~~0.0.1.0';State='Installed'},
          [pscustomobject]@{Name='OpenSSH.Server~~~~0.0.1.0';State='NotPresent'}
        )
      }
      $state = Get-RideOpenSshServerCapabilityState
      $state.Status | Should -BeExactly 'Captured'
      $state.Name | Should -BeExactly 'OpenSSH.Server~~~~0.0.1.0'
      $state.State | Should -BeExactly 'NotPresent'
    }
  }

  It 'captures the exact sshd service fields without starting it' {
    InModuleScope RIDE.OpenSshServerObservation {
      Mock Get-CimInstance { @([pscustomobject]@{Name='sshd';State='Stopped';StartMode='Disabled';StartName='LocalSystem'}) }
      $state = Get-RideOpenSshServerServiceState
      $state.Status | Should -BeExactly 'Captured'
      $state.State | Should -BeExactly 'Stopped'
      $state.StartMode | Should -BeExactly 'Disabled'
      Should -Invoke Get-CimInstance -Times 1 -Exactly
    }
  }

  It 'hashes bounded synthetic server files without returning their bytes' {
    $global:RideSshTestDataRoot = Join-Path $TestDrive 'ssh-data'
    New-Item -ItemType Directory -Path $RideSshTestDataRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $RideSshTestDataRoot 'sshd_config'),'Port 22')
    [IO.File]::WriteAllText((Join-Path $RideSshTestDataRoot 'ssh_host_ed25519_key'),'synthetic-private-key-placeholder')
    InModuleScope RIDE.OpenSshServerObservation {
      Mock Get-RideOpenSshServerDataRoot { $global:RideSshTestDataRoot }
      $state = Get-RideOpenSshServerDataState
      $state.Status | Should -BeExactly 'Captured'
      $state.Files.Count | Should -Be 2
      ($state.Files | Where-Object Name -eq 'sshd_config').Sha256 | Should -Match '^[0-9a-f]{64}$'
      ($state.Files | Where-Object Name -eq 'ssh_host_ed25519_key').PrivateHostKey | Should -BeTrue
      ($state.Files | Get-Member -Name Content -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
    }
    Remove-Variable RideSshTestDataRoot -Scope Global -ErrorAction SilentlyContinue
  }
}
