<#
.SYNOPSIS
  Verify BitLocker route assessments reach the user-facing RIDE view.
.DESCRIPTION
  Supplies synthetic, secret-free state to the engine. No BitLocker cmdlet or
  machine state is accessed.
.EXAMPLE
  $config = New-PesterConfiguration
  $config.Run.Path = '.\tests\BitLockerEngineProjection.Tests.ps1'
  $config.TestRegistry.Enabled = $false
  Invoke-Pester -Configuration $config
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Prerequisites: Repository modules; current state is mocked.
  Version: Test fixture; no independent script version.
#>

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
}

Describe 'BitLocker engine projection' {
  It 'preserves route assessments in user-facing show output' {
    $script:EngineBitLockerState = [pscustomobject]@{
      MountPoint = 'C:'
      VolumeStatus = 'FullyEncrypted'
      VolumeType = 'OperatingSystem'
      EncryptionPercentage = 100
      ProtectionStatus = 'On'
      EncryptionMethod = 'XtsAes128'
      KeyProtectors = @([pscustomobject]@{
        KeyProtectorId = '{44444444-4444-4444-4444-444444444444}'
        KeyProtectorType = 'TpmCertificate'
        RouteAssessment = 'Potential Network Unlock route; verify managed policy and actual boot behavior.'
      })
      StartupPolicy = [pscustomobject]@{ EffectivePolicyEstablished = $false; Interpretation = 'Raw policy only.' }
    }
    Mock Get-RideCurrentState -ModuleName RIDE.Engine { $script:EngineBitLockerState }
    $output = Show-RideOperation -Id 'windows.bitlocker-enrollment' | Out-String -Width 1000
    $output | Should -Match 'Potential Network Unlock route'
    $output | Should -Match 'Recovery passwords are not inspected for display'
  }
}
