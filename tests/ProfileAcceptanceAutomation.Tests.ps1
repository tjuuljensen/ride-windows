<#
.SYNOPSIS
  Verify focused profile acceptance launchers cannot run unguarded on a workstation.
.DESCRIPTION
  Exercises version and required-input/guest-attestation boundaries without VM,
  registry, account, installer, Terminal or screenshot actions.
.EXAMPLE
  Invoke-Pester .\tests\ProfileAcceptanceAutomation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.7.1 on Windows PowerShell 5.1 and PowerShell 7.
  Recovery: No Windows state is changed; the original guest marker is restored.
  Author: RIDE-Windows maintainers. Version: Repository test fixture.
  Changelog: 2026-10-12: Verify acceptance entry-point safety boundaries.
#>


Describe 'Profile acceptance entry-point boundaries' {
  BeforeAll { $script:AcceptanceRoot = Join-Path $PSScriptRoot 'integration' }
  It 'returns the version before any platform or credential checks for <Name>' -ForEach @(
    @{Name='Invoke-RideProfileAcceptance.ps1'; ExpectedVersion='0.1.1'}, @{Name='Invoke-RideProfileVisualAcceptance.ps1'; ExpectedVersion='0.1.1'}, @{Name='Invoke-RideProfileVmAcceptance.ps1'; ExpectedVersion='0.4.0'}, @{Name='Invoke-RideProfileIdentityAcceptance.ps1'; ExpectedVersion='0.1.1'}, @{Name='Invoke-RideUserBinAcceptance.ps1'; ExpectedVersion='0.2.0'}, @{Name='Invoke-RidePersistentUserPathAcceptance.ps1'; ExpectedVersion='0.2.0'}
  ) { & (Join-Path $script:AcceptanceRoot $Name) -Version | Should -Be $ExpectedVersion }
  It 'refuses guest profile preparation without disposable-guest attestation' {
    $previous = $env:RIDE_INTEGRATION_VM
    try {
      $env:RIDE_INTEGRATION_VM = $null
      { & (Join-Path $script:AcceptanceRoot 'Invoke-RideUserBinAcceptance.ps1') -ExpectedComputerName $env:COMPUTERNAME -EvidencePath 'C:\RIDE\ProfileAcceptance\fixture' -DisposableVm } | Should -Throw '*no workstation integration*'
      { & (Join-Path $script:AcceptanceRoot 'Invoke-RideProfileAcceptance.ps1') -Stage Prepare -ExpectedComputerName $env:COMPUTERNAME -EvidencePath 'C:\RIDE\ProfileAcceptance\fixture' -DisposableVm } | Should -Throw '*no workstation integration*'
      { & (Join-Path $script:AcceptanceRoot 'Invoke-RideProfileVisualAcceptance.ps1') -ExpectedComputerName $env:COMPUTERNAME -EvidencePath 'C:\RIDE\ProfileAcceptance\fixture' -DisposableVm } | Should -Throw '*attested disposable guest*'
      { & (Join-Path $script:AcceptanceRoot 'Invoke-RideProfileIdentityAcceptance.ps1') -ExpectedComputerName $env:COMPUTERNAME -EvidencePath 'C:\RIDE\ProfileAcceptance\fixture' -DisposableVm } | Should -Throw '*attested disposable guest*'
      { & (Join-Path $script:AcceptanceRoot 'Invoke-RidePersistentUserPathAcceptance.ps1') -ExpectedComputerName $env:COMPUTERNAME -EvidencePath 'C:\RIDE\ProfileAcceptance\fixture' -DisposableVm } | Should -Throw '*no workstation integration*'
    } finally { $env:RIDE_INTEGRATION_VM = $previous }
  }
  It 'refuses host VM execution before imports when required inputs are absent' {
    { & (Join-Path $script:AcceptanceRoot 'Invoke-RideProfileVmAcceptance.ps1') } | Should -Throw '*required*'
  }
  It 'accepts the persistent user PATH scenario in the host runner without requiring host inputs for version output' {
    & (Join-Path $script:AcceptanceRoot 'Invoke-RideProfileVmAcceptance.ps1') -Scenario PersistentUserPath -Version | Should -Be '0.4.0'
  }
}
