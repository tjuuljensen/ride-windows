<#
.SYNOPSIS
  Verify the read-only RIDE alignment drift report.
.DESCRIPTION
  Checks local pin consistency, supplied peer mismatch reporting, and that
  missing peer information is reported without claiming cross-repository drift.
.EXAMPLE
  Invoke-Pester ./tests/AlignmentDrift.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Changelog: 2026-11-01: Add ALIGN-07 drift report checks.
#>
Describe 'RIDE alignment drift report' {
  BeforeAll {
    $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
    $script:ReportScript = Join-Path $script:RepositoryRoot 'tools/Get-RideAlignmentDrift.ps1'
    $script:Reference = Get-Content -LiteralPath (Join-Path $script:RepositoryRoot 'docs/models/ride-behavior-contract-ref.json') -Raw | ConvertFrom-Json
    $script:Scenarios = Get-Content -LiteralPath (Join-Path $script:RepositoryRoot 'docs/models/behavior-scenarios.json') -Raw | ConvertFrom-Json
  }

  It 'reports current local pins and clearly marks an absent peer comparison' {
    $report = & $script:ReportScript -RepositoryRoot $script:RepositoryRoot
    $report.status | Should -BeExactly 'PeerComparisonUnavailable'
    $report.peerComparison | Should -BeExactly 'unavailable'
    $report.readOnly | Should -BeTrue
    $report.issues.Count | Should -Be 0
    $report.nextAction | Should -Match 'Supply the peer consumer reference'
  }

  It 'reports a deliberate peer contract and scenario mismatch' {
    $peer = [pscustomobject]@{
      contractVersion = '9.9.9'
      sha256 = ('0' * 64)
      scenarioRevision = '9.9.9'
    }
    $peerPath = Join-Path $TestDrive 'peer-contract-ref.json'
    $peer | ConvertTo-Json | Set-Content -LiteralPath $peerPath -Encoding UTF8
    $report = & $script:ReportScript -RepositoryRoot $script:RepositoryRoot -PeerReferencePath $peerPath
    $report.status | Should -BeExactly 'DriftDetected'
    $report.peerComparison | Should -BeExactly 'drift'
    $report.issues.Count | Should -Be 3
    $report.nextAction | Should -Match 'compatibility, evidence and next action'
  }

  It 'rejects a local scenario digest mismatch in fail-on-drift mode' {
    $copyRoot = Join-Path $TestDrive 'copy'
    $null = New-Item -ItemType Directory -Path (Join-Path $copyRoot 'docs/models') -Force
    foreach ($name in @('ride-behavior-contract-ref.json', 'behavior-scenarios.json', 'capability-differences.json')) {
      Copy-Item -LiteralPath (Join-Path $script:RepositoryRoot "docs/models/$name") -Destination (Join-Path $copyRoot "docs/models/$name")
    }
    $contractDirectory = Join-Path $copyRoot 'docs/models'
    Copy-Item -LiteralPath (Join-Path $script:RepositoryRoot 'docs/models/ride-behavior-contract.md') -Destination (Join-Path $contractDirectory 'ride-behavior-contract.md')
    $scenarioPath = Join-Path $contractDirectory 'behavior-scenarios.json'
    $scenarioCopy = Get-Content -LiteralPath $scenarioPath -Raw | ConvertFrom-Json
    $scenarioCopy.contractSha256 = '0' * 64
    $scenarioCopy | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $scenarioPath -Encoding UTF8
    { & $script:ReportScript -RepositoryRoot $copyRoot -FailOnDrift } | Should -Throw '*drift detected*'
  }
}
