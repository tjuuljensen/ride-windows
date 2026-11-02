<#
.SYNOPSIS
  Verify disposable-package Defender observation guards with mocked providers.
.EXAMPLE
  Invoke-Pester ./tests/DefenderAcceptance.Tests.ps1
.NOTES
  Pester 5 on Windows PowerShell 5.1 or PowerShell 7. Version: 0.1.0.
  Changelog: 0.1.0: Cover active protection, detection redaction and failed observation.
  No real Defender provider or payload is accessed.
#>
Import-Module "$PSScriptRoot/integration/RIDE.DefenderAcceptance.psm1" -Force
Describe 'Disposable package Defender evidence' {
  InModuleScope RIDE.DefenderAcceptance {
    BeforeAll {
      function Get-MpComputerStatus {}
      function Get-MpThreatDetection {}
      function Get-MpThreat {}
    }
    BeforeEach {
      Mock Get-MpComputerStatus { [pscustomobject]@{AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$true} }
      Mock Get-MpThreatDetection { @() }
      Mock Get-MpThreat { @() }
    }
    It 'requires active protection with no observed detections' {
      (Get-RideDefenderAcceptanceObservation -Since (Get-Date).AddMinutes(-1)).Passed | Should -BeTrue
    }
    It 'refuses disabled real-time protection' {
      Mock Get-MpComputerStatus { [pscustomobject]@{AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$false} }
      (Get-RideDefenderAcceptanceObservation -Since (Get-Date).AddMinutes(-1)).Passed | Should -BeFalse
    }
    It 'fails on a new detection without retaining resource paths' {
      Mock Get-MpThreatDetection { [pscustomobject]@{DetectionID='synthetic';ThreatID=1;InitialDetectionTime=Get-Date;LastThreatStatusChangeTime=Get-Date;Resources=@('private-path')} }
      $result=Get-RideDefenderAcceptanceObservation -Since (Get-Date).AddMinutes(-1)
      $result.Passed | Should -BeFalse
      ($result|ConvertTo-Json -Depth 5) | Should -Not -Match 'private-path'
    }
    It 'does not turn provider failure into clean evidence' {
      Mock Get-MpThreatDetection { throw 'Provider unavailable' }
      { Get-RideDefenderAcceptanceObservation -Since (Get-Date).AddMinutes(-1) } | Should -Throw '*Provider unavailable*'
    }
  }
}
