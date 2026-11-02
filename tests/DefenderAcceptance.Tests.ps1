<#
.SYNOPSIS
  Verify disposable-package Defender observation guards with mocked providers.
.EXAMPLE
  Invoke-Pester ./tests/DefenderAcceptance.Tests.ps1
.NOTES
  Pester 5 on Windows PowerShell 5.1 or PowerShell 7. Version: 0.2.0.
  Changelog: 0.2.0: Verify sanitized attribution without relaxing active-threat refusal.
    0.1.0: Cover active protection, detection redaction and failed observation.
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
    It 'classifies metadata without retaining paths or allowing a configuration threat' {
      Mock Get-MpThreat { [pscustomobject]@{ThreatID=14994;ThreatName='Synthetic configuration warning';IsActive=$true} }
      Mock Get-MpThreatDetection { [pscustomobject]@{DetectionID='synthetic';ThreatID=14994;InitialDetectionTime=Get-Date;LastThreatStatusChangeTime=Get-Date;Resources=@('file:_C:\Windows\System32\drivers\etc\hosts','file:_C:\RIDE\PortableAcceptance\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\source\private.ps1','file:_C:\RIDE\PortableAcceptance\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\payloads\private.zip','private-path')} }
      $result=Get-RideDefenderAcceptanceObservation -Since (Get-Date).AddMinutes(-1)
      $result.Passed | Should -BeFalse
      $result.ActiveThreats[0].ThreatName | Should -Be 'Synthetic configuration warning'
      @($result.Detections[0].ResourceCategories) | Should -HaveCount 4
      $result.Detections[0].ResourceCategories | Should -Contain 'WindowsHostsFile'
      $result.Detections[0].ResourceCategories | Should -Contain 'StagedSource'
      $result.Detections[0].ResourceCategories | Should -Contain 'StagedPayload'
      ($result|ConvertTo-Json -Depth 6) | Should -Not -Match 'private|System32|aaaaaaaa'
    }
  }
}
