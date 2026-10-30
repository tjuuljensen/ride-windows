<#
.SYNOPSIS
  Verify guarded OpenSSH Server capability installation before target support.
.DESCRIPTION
  Mocks all target observations, servicing, service, firewall, privilege and snapshot
  providers. No Windows capability, service, firewall or SSH data is changed.
.EXAMPLE
  Invoke-Pester .\tests\OpenSshServerCapabilityLifecycle.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Native Windows 11 and Server 2025 acceptance remains deferred.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.OpenSshServerCapabilityLifecycle.psm1') -Force
}

Describe 'Guarded OpenSSH Server capability installation candidate' {
  BeforeEach {
    $global:RideSshInstallRoot = Join-Path $TestDrive 'install-state'
    if (Test-Path -LiteralPath $global:RideSshInstallRoot) { Remove-Item -LiteralPath $global:RideSshInstallRoot -Recurse -Force }
    $global:RideSshInstallCalls = 0
    $global:RideSshRemoveCalls = 0
    $global:RideSshFirewallCalls = 0
    $global:RideSshInstallState = [pscustomobject]@{
      Context = [pscustomobject]@{ ComputerName = 'TEST-VM'; Build = '26100'; EditionId = 'Professional'; UpdateBuildRevision = 123; ProductType = 'WinNT'; NativeProcess = $true }
      Capability = [pscustomobject]@{ Name = 'OpenSSH.Server~~~~0.0.1.0'; State = 'NotPresent' }
      ServiceStatus = 'NotFound'
      Service = $null
      FirewallStatus = 'NotFound'
      Firewall = $null
      ServerData = [pscustomobject]@{ Status = 'NotFound'; Root = 'C:\ProgramData\ssh'; Files = @(); TotalBytes = 0 }
    }
    Mock Test-RideOpenSshServerInstallAdministrator -ModuleName RIDE.OpenSshServerCapabilityLifecycle { $true }
    Mock Test-RideOpenSshServerInstallPendingReboot -ModuleName RIDE.OpenSshServerCapabilityLifecycle { $false }
    Mock Get-RideOpenSshServerState -ModuleName RIDE.OpenSshServerCapabilityLifecycle {
      [pscustomobject]@{
        WindowsContext = $global:RideSshInstallState.Context
        Providers = @(
          [pscustomobject]@{ Name = 'Capability'; Status = 'Captured'; Observation = $global:RideSshInstallState.Capability }
          [pscustomobject]@{ Name = 'Service'; Status = $global:RideSshInstallState.ServiceStatus; Observation = $global:RideSshInstallState.Service }
          [pscustomobject]@{ Name = 'Firewall'; Status = $global:RideSshInstallState.FirewallStatus; Observation = $global:RideSshInstallState.Firewall }
          [pscustomobject]@{ Name = 'ServerData'; Status = $global:RideSshInstallState.ServerData.Status; Observation = $global:RideSshInstallState.ServerData }
        )
      }
    }
    Mock Initialize-RideOpenSshServerInstallStateDirectory -ModuleName RIDE.OpenSshServerCapabilityLifecycle {
      New-Item -ItemType Directory -Path $global:RideSshInstallRoot -Force | Out-Null
      $global:RideSshInstallRoot
    }
    Mock Get-RideOpenSshServerInstallStateDirectory -ModuleName RIDE.OpenSshServerCapabilityLifecycle { $global:RideSshInstallRoot }
    Mock Add-WindowsCapability -ModuleName RIDE.OpenSshServerCapabilityLifecycle {
      $global:RideSshInstallCalls++
      $global:RideSshInstallState.Capability.State = 'Installed'
      $global:RideSshInstallState.ServiceStatus = 'Captured'
      $global:RideSshInstallState.Service = [pscustomobject]@{ Name = 'sshd'; State = 'Stopped'; StartMode = 'Manual'; StartName = 'LocalSystem' }
      $global:RideSshInstallState.FirewallStatus = 'Captured'
      $global:RideSshInstallState.Firewall = [pscustomobject]@{ Name = 'OpenSSH-Server-In-TCP'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '22'; PolicyStoreSourceType = 'Local'; PolicyStoreSource = 'PersistentStore' }
    }
    Mock Set-NetFirewallRule -ModuleName RIDE.OpenSshServerCapabilityLifecycle {
      $global:RideSshFirewallCalls++
      $global:RideSshInstallState.Firewall.Enabled = [string]$Enabled
    }
    Mock Remove-WindowsCapability -ModuleName RIDE.OpenSshServerCapabilityLifecycle {
      $global:RideSshRemoveCalls++
      $global:RideSshInstallState.Capability.State = 'NotPresent'
      $global:RideSshInstallState.ServiceStatus = 'NotFound'
      $global:RideSshInstallState.Service = $null
      $global:RideSshInstallState.FirewallStatus = 'NotFound'
      $global:RideSshInstallState.Firewall = $null
      $global:RideSshInstallState.ServerData = [pscustomobject]@{ Status = 'NotFound'; Root = 'C:\ProgramData\ssh'; Files = @(); TotalBytes = 0 }
    }
    Mock Remove-NetFirewallRule -ModuleName RIDE.OpenSshServerCapabilityLifecycle {
      $global:RideSshFirewallCalls++
      $global:RideSshInstallState.FirewallStatus = 'NotFound'
      $global:RideSshInstallState.Firewall = $null
    }
    Mock Start-Service -ModuleName RIDE.OpenSshServerCapabilityLifecycle { throw 'Installation candidate must never start sshd.' }
  }

  It 'installs the exact capability, leaves sshd stopped and disables the newly created rule' {
    $result = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $result.Status | Should -BeExactly 'Installed'
    $result.PostStateVerified | Should -BeTrue
    $result.ServiceStarted | Should -BeFalse
    $result.FirewallChanged | Should -BeTrue
    $global:RideSshInstallCalls | Should -Be 1
    $global:RideSshFirewallCalls | Should -Be 1
    $global:RideSshInstallState.Service.State | Should -BeExactly 'Stopped'
    $global:RideSshInstallState.Firewall.Enabled | Should -BeExactly 'False'
    $snapshot = Get-Content -LiteralPath $result.SnapshotPath -Raw | ConvertFrom-Json
    $snapshot.BeforeFirewallStatus | Should -BeExactly 'NotFound'
    $snapshot.InstallStatus | Should -BeExactly 'Completed'
    $snapshot.RemovalSupported | Should -BeTrue
  }

  It 'uses a caller-supplied run ID for both guarded snapshots' {
    $runId=[guid]::NewGuid().ToString('N')
    $result=Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -RunId $runId -Confirm:$false
    $result.RunId | Should -BeExactly $runId
    (Split-Path -Leaf $result.SnapshotPath) | Should -BeExactly ($runId+'-completed.json')
    Test-Path -LiteralPath (Join-Path $global:RideSshInstallRoot ($runId+'-completed.json')) | Should -BeTrue
  }

  It 'removes only a matching install and verifies return to captured absence' {
    $installed = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $removed = Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $removed.Status | Should -BeExactly 'Removed'
    $removed.RecoverySupported | Should -BeTrue
    $global:RideSshRemoveCalls | Should -Be 1
    $global:RideSshInstallState.Capability.State | Should -BeExactly 'NotPresent'
    $global:RideSshInstallState.ServiceStatus | Should -BeExactly 'NotFound'
    $global:RideSshInstallState.FirewallStatus | Should -BeExactly 'NotFound'
    $global:RideSshInstallState.ServerData.Status | Should -BeExactly 'NotFound'
  }

  It 'removes only the disabled rule created by the installation when servicing leaves it behind' {
    $installed = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    Mock Remove-WindowsCapability -ModuleName RIDE.OpenSshServerCapabilityLifecycle {
      $global:RideSshRemoveCalls++
      $global:RideSshInstallState.Capability.State = 'NotPresent'
      $global:RideSshInstallState.ServiceStatus = 'NotFound'
      $global:RideSshInstallState.Service = $null
      $global:RideSshInstallState.ServerData = [pscustomobject]@{ Status = 'NotFound'; Root = 'C:\ProgramData\ssh'; Files = @(); TotalBytes = 0 }
    }
    $removed = Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $removed.Status | Should -BeExactly 'Removed'
    $global:RideSshFirewallCalls | Should -Be 2
    $global:RideSshInstallState.FirewallStatus | Should -BeExactly 'NotFound'
  }

  It 'retries only the exact disabled firewall cleanup after capability removal was partial' {
    $installed = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    Mock Remove-WindowsCapability -ModuleName RIDE.OpenSshServerCapabilityLifecycle {
      $global:RideSshRemoveCalls++
      $global:RideSshInstallState.Capability.State = 'NotPresent'
      $global:RideSshInstallState.ServiceStatus = 'NotFound'
      $global:RideSshInstallState.Service = $null
      $global:RideSshInstallState.ServerData = [pscustomobject]@{ Status = 'NotFound'; Root = 'C:\ProgramData\ssh'; Files = @(); TotalBytes = 0 }
    }
    Mock Remove-NetFirewallRule -ModuleName RIDE.OpenSshServerCapabilityLifecycle {
      $global:RideSshFirewallCalls++
      if ($global:RideSshFirewallCalls -eq 2) { throw 'simulated firewall cleanup failure' }
      $global:RideSshInstallState.FirewallStatus = 'NotFound'
      $global:RideSshInstallState.Firewall = $null
    }

    { Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false } | Should -Throw '*removal may be partial*'
    $global:RideSshInstallState.Capability.State | Should -BeExactly 'NotPresent'
    $global:RideSshInstallState.FirewallStatus | Should -BeExactly 'Captured'
    $global:RideSshInstallState.Firewall.Enabled | Should -BeExactly 'False'
    $global:RideSshFirewallCalls | Should -Be 2

    $retry = Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $retry.Status | Should -BeExactly 'RecoveredPartialRemoval'
    $retry.PostStateVerified | Should -BeTrue
    $global:RideSshRemoveCalls | Should -Be 1
    $global:RideSshFirewallCalls | Should -Be 3
    $global:RideSshInstallState.FirewallStatus | Should -BeExactly 'NotFound'
    Test-Path -LiteralPath (Join-Path $global:RideSshInstallRoot ($installed.RunId + '-removed.json')) | Should -BeTrue
  }

  It 'refuses partial-removal recovery if an operator re-enables the remaining rule' {
    $installed = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $global:RideSshInstallState.Capability.State = 'NotPresent'
    $global:RideSshInstallState.ServiceStatus = 'NotFound'
    $global:RideSshInstallState.Service = $null
    $global:RideSshInstallState.ServerData = [pscustomobject]@{ Status = 'NotFound'; Root = 'C:\ProgramData\ssh'; Files = @(); TotalBytes = 0 }
    $global:RideSshInstallState.Firewall.Enabled = 'True'

    { Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false } | Should -Throw '*differs from the saved disabled rule*'
    $global:RideSshRemoveCalls | Should -Be 0
    $global:RideSshFirewallCalls | Should -Be 1
    $global:RideSshInstallState.FirewallStatus | Should -BeExactly 'Captured'
    $global:RideSshInstallState.Firewall.Enabled | Should -BeExactly 'True'
    Test-Path -LiteralPath (Join-Path $global:RideSshInstallRoot ($installed.RunId + '-removed.json')) | Should -BeFalse
  }

  It 'previews removal without calling servicing or changing saved state' {
    $installed = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $preview = Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -WhatIf
    $preview.Status | Should -BeExactly 'WhatIf'
    $global:RideSshRemoveCalls | Should -Be 0
    $global:RideSshInstallState.Capability.State | Should -BeExactly 'Installed'
  }

  It 'refuses removal when service state drifted after installation' {
    $installed = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $global:RideSshInstallState.Service.State = 'Running'
    { Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false } | Should -Throw '*service state drifted*'
    $global:RideSshRemoveCalls | Should -Be 0
  }

  It 'refuses removal when an operator added server data after installation' {
    $installed = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $global:RideSshInstallState.ServerData = [pscustomobject]@{ Status = 'Captured'; Root = 'C:\ProgramData\ssh'; Files = @([pscustomobject]@{ Name = 'sshd_config'; Length = 7; Sha256 = ('c' * 64); PrivateHostKey = $false }); TotalBytes = 7 }
    { Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false } | Should -Throw '*data drifted*'
    $global:RideSshRemoveCalls | Should -Be 0
  }

  It 'records idempotent repeated removal only for its own completed run' {
    $installed = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $null = Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $again = Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $again.Status | Should -BeExactly 'AlreadyRemoved'
    $global:RideSshRemoveCalls | Should -Be 1
  }

  It 'resolves the active capability owner from its completed snapshot and ignores removed ownership' {
    $installed = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    Get-RideOpenSshServerActiveInstallRunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional | Should -BeExactly $installed.RunId
    $null = Remove-RideOpenSshServerCapability -RunId $installed.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    { Get-RideOpenSshServerActiveInstallRunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional } | Should -Throw '*No reversible RIDE-owned OpenSSH Server installation matches this target*'
  }

  It 'previews without saving state or invoking servicing and firewall providers' {
    $result = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -WhatIf
    $result.Status | Should -BeExactly 'WhatIf'
    $global:RideSshInstallCalls | Should -Be 0
    $global:RideSshFirewallCalls | Should -Be 0
    (Test-Path -LiteralPath $global:RideSshInstallRoot) | Should -BeFalse
  }

  It 'preserves a pre-existing enabled TCP/22 rule without changing it' {
    $global:RideSshInstallState.FirewallStatus = 'Captured'
    $global:RideSshInstallState.Firewall = [pscustomobject]@{ Name = 'OpenSSH-Server-In-TCP'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '22'; PolicyStoreSourceType = 'Local'; PolicyStoreSource = 'PersistentStore' }
    $result = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $result.PostStateVerified | Should -BeTrue
    $result.FirewallChanged | Should -BeFalse
    $global:RideSshFirewallCalls | Should -Be 0
    $global:RideSshInstallState.Firewall.Enabled | Should -BeExactly 'True'
    $global:RideSshInstallState.Service.State | Should -BeExactly 'Stopped'
  }

  It 'does not service an already installed Server capability' {
    $global:RideSshInstallState.Capability.State = 'Installed'
    $result = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $result.Status | Should -BeExactly 'AlreadyPresent'
    $global:RideSshInstallCalls | Should -Be 0
    $global:RideSshFirewallCalls | Should -Be 0
  }

  It 'refuses a running service when the capability is reported absent' {
    $global:RideSshInstallState.ServiceStatus = 'Captured'
    $global:RideSshInstallState.Service = [pscustomobject]@{ Name = 'sshd'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem' }
    { Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false } | Should -Throw '*service is running*'
    $global:RideSshInstallCalls | Should -Be 0
  }

  It 'passes explicit local source parameters and no Windows Update fallback when requested' {
    $result = Install-RideOpenSshServerCapability -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Source 'D:\Sources\FOD' -LimitAccess -Confirm:$false
    Should -Invoke Add-WindowsCapability -ModuleName RIDE.OpenSshServerCapabilityLifecycle -Times 1 -ParameterFilter { $Online -and $Name -ceq 'OpenSSH.Server~~~~0.0.1.0' -and $Source -ceq 'D:\Sources\FOD' -and $LimitAccess }
    $result.PostStateVerified | Should -BeTrue
  }
}
