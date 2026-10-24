<#
.SYNOPSIS
  Verify the unregistered OpenSSH Server activation/restore candidate.
.DESCRIPTION
  Mocks all service, firewall, target, privilege and observation providers. No Windows
  service, firewall rule, capability, host key or configuration is changed.
.EXAMPLE
  Invoke-Pester .\tests\OpenSshServerLifecycle.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Native Windows 11 and Server 2025 acceptance remains deferred.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.OpenSshServerLifecycle.psm1') -Force
}

Describe 'Guarded OpenSSH Server activation candidate' {
  BeforeEach {
    $global:RideSshActivationRoot = Join-Path $TestDrive 'activation-state'
    if (Test-Path -LiteralPath $global:RideSshActivationRoot) { Remove-Item -LiteralPath $global:RideSshActivationRoot -Recurse -Force }
    $global:RideSshActivationNativeCalls = 0
    $global:RideSshActivationState = [pscustomobject]@{
      Context = [pscustomobject]@{ ComputerName = 'TEST-VM'; Build = '26100'; EditionId = 'Professional'; UpdateBuildRevision = 123; ProductType = 'WinNT'; NativeProcess = $true }
      Capability = [pscustomobject]@{ Name = 'OpenSSH.Server~~~~0.0.1.0'; State = 'Installed' }
      Service = [pscustomobject]@{ Name = 'sshd'; State = 'Stopped'; StartMode = 'Manual'; StartName = 'LocalSystem' }
      FirewallStatus = 'Captured'
      Firewall = [pscustomobject]@{ Name = 'OpenSSH-Server-In-TCP'; Enabled = 'False'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '22'; PolicyStoreSourceType = 'Local'; PolicyStoreSource = 'PersistentStore' }
      ServerData = [pscustomobject]@{ Status = 'Captured'; Root = 'C:\ProgramData\ssh'; Files = @([pscustomobject]@{ Name = 'sshd_config'; Length = 5; Sha256 = ('a' * 64); PrivateHostKey = $false }); TotalBytes = 5 }
    }

    Mock Test-RideOpenSshServerActivationAdministrator -ModuleName RIDE.OpenSshServerLifecycle { $true }
    Mock Test-RideOpenSshServerActivationPendingReboot -ModuleName RIDE.OpenSshServerLifecycle { $false }
    Mock Get-RideOpenSshServerState -ModuleName RIDE.OpenSshServerLifecycle {
      [pscustomobject]@{
        WindowsContext = $global:RideSshActivationState.Context
        Providers = @(
          [pscustomobject]@{ Name = 'Capability'; Status = 'Captured'; Observation = $global:RideSshActivationState.Capability }
          [pscustomobject]@{ Name = 'Service'; Status = 'Captured'; Observation = $global:RideSshActivationState.Service }
          [pscustomobject]@{ Name = 'Firewall'; Status = $global:RideSshActivationState.FirewallStatus; Observation = $global:RideSshActivationState.Firewall }
          [pscustomobject]@{ Name = 'ServerData'; Status = [string]$global:RideSshActivationState.ServerData.Status; Observation = $global:RideSshActivationState.ServerData }
        )
      }
    }
    Mock Initialize-RideOpenSshServerActivationStateDirectory -ModuleName RIDE.OpenSshServerLifecycle {
      New-Item -ItemType Directory -Path $global:RideSshActivationRoot -Force | Out-Null
      $global:RideSshActivationRoot
    }
    Mock Get-RideOpenSshServerActivationStateDirectory -ModuleName RIDE.OpenSshServerLifecycle { $global:RideSshActivationRoot }
    Mock Set-Service -ModuleName RIDE.OpenSshServerLifecycle {
      $global:RideSshActivationNativeCalls++
      $global:RideSshActivationState.Service.StartMode = if ($StartupType -eq 'Automatic') { 'Auto' } else { $StartupType }
    }
    Mock Start-Service -ModuleName RIDE.OpenSshServerLifecycle {
      $global:RideSshActivationNativeCalls++
      $global:RideSshActivationState.Service.State = 'Running'
      $global:RideSshActivationState.ServerData.Files += [pscustomobject]@{ Name = 'ssh_host_ed25519_key'; Length = 32; Sha256 = ('b' * 64); PrivateHostKey = $true }
    }
    Mock Stop-Service -ModuleName RIDE.OpenSshServerLifecycle {
      $global:RideSshActivationNativeCalls++
      $global:RideSshActivationState.Service.State = 'Stopped'
    }
    Mock Set-NetFirewallRule -ModuleName RIDE.OpenSshServerLifecycle {
      $global:RideSshActivationNativeCalls++
      $global:RideSshActivationState.Firewall.Enabled = [string]$Enabled
    }
  }

  It 'starts only the selected service state and explicitly selected firewall state' {
    $result = Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Automatic -InboundRuleState Enabled -Confirm:$false
    $result.Status | Should -BeExactly 'Applied'
    $result.PostStateVerified | Should -BeTrue
    $result.ServerDataChanged | Should -BeTrue
    $result.ExactHostKeyOrConfigurationRecovery | Should -BeFalse
    $global:RideSshActivationState.Service.State | Should -BeExactly 'Running'
    $global:RideSshActivationState.Service.StartMode | Should -BeExactly 'Auto'
    $global:RideSshActivationState.Firewall.Enabled | Should -BeExactly 'True'
    $record = Get-Content -LiteralPath $result.SnapshotPath -Raw | ConvertFrom-Json
    $record.BeforeService.State | Should -BeExactly 'Stopped'
    $record.BeforeServerData.Files.Name | Should -Contain 'sshd_config'
    (Get-Content -LiteralPath $result.SnapshotPath -Raw) | Should -Not -Match 'synthetic private key bytes'
  }

  It 'restores service and firewall literals while retaining first-start server data' {
    $result = Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Automatic -InboundRuleState Enabled -Confirm:$false
    $restored = Restore-RideOpenSshServerActivation -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $restored.Status | Should -BeExactly 'Restored'
    $restored.PostStateVerified | Should -BeTrue
    $restored.ServerDataChanged | Should -BeTrue
    $restored.ServerDataCleanupPerformed | Should -BeFalse
    $global:RideSshActivationState.Service.State | Should -BeExactly 'Stopped'
    $global:RideSshActivationState.Service.StartMode | Should -BeExactly 'Manual'
    $global:RideSshActivationState.Firewall.Enabled | Should -BeExactly 'False'
    $global:RideSshActivationState.ServerData.Files.Name | Should -Contain 'ssh_host_ed25519_key'
  }

  It 'previews without saving state or calling Windows providers' {
    $result = Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Manual -InboundRuleState Keep -WhatIf
    $result.Status | Should -BeExactly 'WhatIf'
    $result.InboundAccessWillBeAllowed | Should -BeFalse
    $global:RideSshActivationNativeCalls | Should -Be 0
    (Test-Path -LiteralPath $global:RideSshActivationRoot) | Should -BeFalse
  }

  It 'refuses a firewall request when the exact local rule is absent' {
    $global:RideSshActivationState.FirewallStatus = 'NotFound'
    $global:RideSshActivationState.Firewall = $null
    { Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Manual -InboundRuleState Enabled -Confirm:$false } | Should -Throw '*must already exist*'
    $global:RideSshActivationNativeCalls | Should -Be 0
    (Test-Path -LiteralPath $global:RideSshActivationRoot) | Should -BeFalse
  }

  It 'refuses a changed service identity before restoring' {
    $result = Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Automatic -InboundRuleState Keep -Confirm:$false
    $global:RideSshActivationState.Service.StartName = 'OtherAccount'
    $callsBeforeRestore = $global:RideSshActivationNativeCalls
    { Restore-RideOpenSshServerActivation -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false } | Should -Throw '*drifted*'
    $global:RideSshActivationNativeCalls | Should -Be $callsBeforeRestore
  }

  It 'restores a partial start when only the requested startup mode was applied' {
    Mock Start-Service -ModuleName RIDE.OpenSshServerLifecycle { throw 'Synthetic service start failure' }
    { Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Automatic -InboundRuleState Keep -Confirm:$false } | Should -Throw '*saving recovery run*'
    $snapshot = Get-ChildItem -LiteralPath $global:RideSshActivationRoot -Filter '*.json' | Select-Object -First 1
    $snapshot | Should -Not -BeNullOrEmpty
    $runId = [IO.Path]::GetFileNameWithoutExtension($snapshot.Name)
    $restored = Restore-RideOpenSshServerActivation -RunId $runId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $restored.Status | Should -BeExactly 'Restored'
    $global:RideSshActivationState.Service.State | Should -BeExactly 'Stopped'
    $global:RideSshActivationState.Service.StartMode | Should -BeExactly 'Manual'
  }

  It 'previews restore without changing service, firewall or saved state' {
    $result = Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Automatic -InboundRuleState Enabled -Confirm:$false
    $callsBeforePreview = $global:RideSshActivationNativeCalls
    $preview = Restore-RideOpenSshServerActivation -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -WhatIf
    $preview.Status | Should -BeExactly 'WhatIf'
    $global:RideSshActivationNativeCalls | Should -Be $callsBeforePreview
    $global:RideSshActivationState.Service.State | Should -BeExactly 'Running'
    $global:RideSshActivationState.Firewall.Enabled | Should -BeExactly 'True'
    (Test-Path -LiteralPath $result.SnapshotPath) | Should -BeTrue
  }

  It 'returns AlreadyRestored without changing retained generated server data' {
    $result = Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Automatic -InboundRuleState Enabled -Confirm:$false
    $null = Restore-RideOpenSshServerActivation -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $callsAfterRestore = $global:RideSshActivationNativeCalls
    $repeat = Restore-RideOpenSshServerActivation -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -Confirm:$false
    $repeat.Status | Should -BeExactly 'AlreadyRestored'
    $repeat.ServerDataChanged | Should -BeTrue
    $global:RideSshActivationNativeCalls | Should -Be $callsAfterRestore
  }

  It 'refuses a firewall rule whose protocol no longer matches the owned rule identity' {
    $global:RideSshActivationState.Firewall.Protocol = 'UDP'
    { Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Manual -InboundRuleState Disabled -Confirm:$false } | Should -Throw '*exact local TCP/22 rule*'
    $global:RideSshActivationNativeCalls | Should -Be 0
    (Test-Path -LiteralPath $global:RideSshActivationRoot) | Should -BeFalse
  }

  It 'refuses operation without an already elevated administrator session' {
    Mock Test-RideOpenSshServerActivationAdministrator -ModuleName RIDE.OpenSshServerLifecycle { $false }
    { Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Manual -InboundRuleState Keep -Confirm:$false } | Should -Throw '*already elevated*'
    $global:RideSshActivationNativeCalls | Should -Be 0
    (Test-Path -LiteralPath $global:RideSshActivationRoot) | Should -BeFalse
  }

  It 'refuses a servicing restart or absent capability before writing state' {
    Mock Test-RideOpenSshServerActivationPendingReboot -ModuleName RIDE.OpenSshServerLifecycle { $true }
    { Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Manual -InboundRuleState Keep -Confirm:$false } | Should -Throw '*restart is pending*'
    Mock Test-RideOpenSshServerActivationPendingReboot -ModuleName RIDE.OpenSshServerLifecycle { $false }
    $global:RideSshActivationState.Capability.State = 'NotPresent'
    { Invoke-RideOpenSshServerActivation -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Manual -InboundRuleState Keep -Confirm:$false } | Should -Throw '*must already be installed*'
    $global:RideSshActivationNativeCalls | Should -Be 0
    (Test-Path -LiteralPath $global:RideSshActivationRoot) | Should -BeFalse
  }
}
