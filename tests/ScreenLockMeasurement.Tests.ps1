<#
.SYNOPSIS
  Validate screen-lock measurement safety and arithmetic using synthetic fixtures.
.DESCRIPTION
  Does not launch keep-awake tools, send input or measure the developer machine.
  Tests guards, download-only preview, manifest completion and memory aggregation.
.EXAMPLE
  Invoke-Pester .\tests\ScreenLockMeasurement.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester test results.
.NOTES
  Compatibility: Pester 5.x, Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Author: RIDE-Windows maintainers. Version: 0.1.1
  Versioning exception: Pester fixture, not a standalone management CLI.
  Changelog: 0.1.1: Add fractional timing and ambiguous locale regression coverage.
  0.1.0: Add synthetic measurement and no-launch safety regressions.
#>
BeforeAll {
  $script:integration = Join-Path (Split-Path $PSScriptRoot -Parent) 'tests/integration'
  $script:capture = Join-Path $script:integration 'Invoke-RideScreenLockCapture.ps1'
  $script:acquire = Join-Path $script:integration 'New-RideScreenLockInputs.ps1'
  $script:summary = Join-Path $script:integration 'Get-RideScreenLockSummary.ps1'
  $script:snapshot = Join-Path $script:integration 'Export-RideScreenLockSnapshot.ps1'
  $script:fixture = Join-Path $TestDrive 'synthetic'
  [void](New-Item -ItemType Directory -Path $script:fixture)
  @{ CaseId = 'synthetic'; RunNumber = 1; Status = 'Captured' } | ConvertTo-Json | Set-Content (Join-Path $script:fixture 'metadata.json')
  @(@{ Key = '3:30'; Name = 'conhost.exe' }) | ConvertTo-Json | Set-Content (Join-Path $script:fixture 'processes.json')
  $rows = foreach ($sample in @(1,2)) {
    foreach ($entry in @(
      @{ Key = '1:10'; Role = 'Workload'; Ws = @(10,100); Io = @(100,200) },
      @{ Key = '2:20'; Role = 'Workload'; Ws = @(100,10); Io = @(10,30) },
      @{ Key = '3:30'; Role = 'ConsoleCandidate'; Ws = @(5,7); Io = @(10,40) },
      @{ Key = '4:40'; Role = 'Sampler'; Ws = @(1000,1001); Io = @(5000,7000) }
    )) {
      [pscustomobject]@{
        Sample = $sample; Phase = 'Steady'; ProcessKey = $entry.Key; Role = $entry.Role
        WorkingSetBytes = $entry.Ws[$sample - 1]; PrivateBytes = $entry.Ws[$sample - 1] / 2
        CumulativeIoWriteBytes = $entry.Io[$sample - 1]; GapSeconds = 1
      }
    }
  }
  $rows | Export-Csv (Join-Path $script:fixture 'samples.csv') -NoTypeInformation
}
Describe 'Measurement safety and discoverability' {
  It 'prints versions before any operational work' {
    Mock Start-Process { throw 'Must not launch' }
    Mock Invoke-WebRequest { throw 'Must not download' }
    foreach ($path in @($script:capture,$script:acquire,$script:summary,$script:snapshot)) {
      $expectedVersion = switch ([IO.Path]::GetFileName($path)) {
        'Invoke-RideScreenLockCapture.ps1' { '0.1.2' }
        'Get-RideScreenLockSummary.ps1' { '0.1.1' }
        default { '0.1.0' }
      }
      (& $path -Version) | Should -Be $expectedVersion
    }
    Should -Invoke Start-Process -Times 0
    Should -Invoke Invoke-WebRequest -Times 0
  }
  It 'rejects a mismatched or unattested machine before querying or launching' {
    Mock Start-Process { throw 'Must not launch' }
    Mock Get-CimInstance { throw 'Must not query' }
    { & $script:capture -ManifestPath missing -CaseId missing -ConditionsPath missing -OutputDirectory missing -ExpectedComputerName 'not-this-machine' -DisposableVm } | Should -Throw '*attestation*'
    { & $script:capture -ManifestPath missing -CaseId missing -ConditionsPath missing -OutputDirectory missing -ExpectedComputerName $env:COMPUTERNAME } | Should -Throw '*attestation*'
    Should -Invoke Start-Process -Times 0
    Should -Invoke Get-CimInstance -Times 0
  }
  It 'rejects snapshot writes on an unmatched machine' {
    Mock Get-CimInstance { throw 'Must not query' }
    { & $script:snapshot -ExpectedComputerName 'not-this-machine' -DisposableVm -FileRoot $TestDrive -OutputPath (Join-Path $TestDrive 'forbidden.json') } | Should -Throw '*attestation*'
    Test-Path (Join-Path $TestDrive 'forbidden.json') | Should -BeFalse
    Should -Invoke Get-CimInstance -Times 0
  }
  It 'makes download preview nonmutating' {
    Mock Invoke-WebRequest { throw 'Must not download' }
    $destination = Join-Path $TestDrive 'not-acquired'
    & $script:acquire -Destination $destination -WhatIf
    Test-Path $destination | Should -BeFalse
    Should -Invoke Invoke-WebRequest -Times 0
  }
  It 'completes case IDs from the supplied manifest without launching' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ Cases = @(@{ Id = 'ps51-light' }, @{ Id = 'ps7-light' }, @{ Id = 'zhorn64-60' }, @{ Id = 'ps51-light' }) } | ConvertTo-Json -Depth 4 | Set-Content $manifestPath
    $line = "& '$script:capture' -ManifestPath '$manifestPath' -CaseId PS"
    $result = TabExpansion2 -inputScript $line -cursorColumn $line.Length
    @($result.CompletionMatches.CompletionText).Count | Should -Be 2
    $result.CompletionMatches.CompletionText | Should -Contain 'ps51-light'
    $result.CompletionMatches.CompletionText | Should -Contain 'ps7-light'
  }
}
Describe 'Simultaneous footprint arithmetic' {
  It 'rejects legacy decimal commas rather than reading them as thousands' {
    $legacy = Join-Path $TestDrive 'legacy-locale'
    [void](New-Item -ItemType Directory -Path $legacy)
    Copy-Item -LiteralPath (Join-Path $script:fixture 'metadata.json'),(Join-Path $script:fixture 'processes.json') -Destination $legacy
    $rows = Import-Csv -LiteralPath (Join-Path $script:fixture 'samples.csv')
    foreach ($row in $rows) { $row.GapSeconds = '0,125' }
    $rows | Export-Csv (Join-Path $legacy 'samples.csv') -NoTypeInformation
    { & $script:summary -RunDirectory $legacy } | Should -Throw '*locale-specific timing*'
  }
  It 'reads invariant fractional sampling intervals under Danish culture' {
    $fractional = Join-Path $TestDrive 'fractional'
    [void](New-Item -ItemType Directory -Path $fractional)
    Copy-Item -LiteralPath (Join-Path $script:fixture 'metadata.json'),(Join-Path $script:fixture 'processes.json') -Destination $fractional
    $rows = Import-Csv -LiteralPath (Join-Path $script:fixture 'samples.csv')
    foreach ($row in $rows) { $row.GapSeconds = '0.125' }
    $rows | Export-Csv (Join-Path $fractional 'samples.csv') -NoTypeInformation
    $priorCulture = [Threading.Thread]::CurrentThread.CurrentCulture
    try {
      [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('da-DK')
      $result = & $script:summary -RunDirectory $fractional
      ($result.Memory | Where-Object Group -eq 'WorkloadWithAssignedConsole').GapSeconds.Median | Should -Be 0.125
    }
    finally { [Threading.Thread]::CurrentThread.CurrentCulture = $priorCulture }
  }
  It 'does not sum nonsimultaneous per-process peaks or charge the sampler' {
    $result = & $script:summary -RunDirectory $script:fixture
    $workload = $result.Memory | Where-Object Group -eq 'WorkloadWithAssignedConsole'
    $workload.WorkingSetBytes.Median | Should -Be 110
    $workload.WorkingSetBytes.SampledPeak | Should -Be 110
    $workload.PrivateBytes.Median | Should -Be 55
    $result.BehaviorVerified | Should -BeFalse
  }
  It 'adds only explicitly assigned console identities' {
    $result = & $script:summary -RunDirectory $script:fixture -AssignedConsoleKey '3:30'
    $workload = $result.Memory | Where-Object Group -eq 'WorkloadWithAssignedConsole'
    $workload.WorkingSetBytes.Median | Should -Be 116
    $workload.WorkingSetBytes.SampledPeak | Should -Be 117
    $workload.WorkingSetBytes.P95 | Should -Be 117
    ($result.Memory | Where-Object Group -eq 'Sampler').WorkingSetBytes.SampledPeak | Should -Be 1001
  }
  It 'rejects an unreviewed process key rather than silently adding it' {
    { & $script:summary -RunDirectory $script:fixture -AssignedConsoleKey '1:10' } | Should -Throw '*Unknown console*'
  }
  It 'keeps per-process counter deltas separate from physical disk traffic' {
    $result = & $script:summary -RunDirectory $script:fixture -AssignedConsoleKey '3:30'
    ($result.IoLowerBounds | Where-Object ProcessKey -eq '1:10').ObservedIoWriteDeltaBytes | Should -Be 100
    ($result.IoLowerBounds | Where-Object ProcessKey -eq '2:20').ObservedIoWriteDeltaBytes | Should -Be 20
    $result.IoLowerBounds.ProcessKey | Should -Not -Contain '4:40'
    $result.Limits | Should -Match 'not physical disk traffic'
  }
  It 'excludes and counts incomplete private-memory totals instead of inventing zero usage' {
    $incomplete = Join-Path $TestDrive 'incomplete'
    [void](New-Item -ItemType Directory -Path $incomplete)
    Copy-Item -LiteralPath (Join-Path $script:fixture 'metadata.json'),(Join-Path $script:fixture 'processes.json') -Destination $incomplete
    $rows = Import-Csv -LiteralPath (Join-Path $script:fixture 'samples.csv')
    ($rows | Where-Object { $_.Sample -eq '1' -and $_.ProcessKey -eq '1:10' }).PrivateBytes = ''
    $rows | Export-Csv (Join-Path $incomplete 'samples.csv') -NoTypeInformation
    $result = & $script:summary -RunDirectory $incomplete
    $workload = $result.Memory | Where-Object Group -eq 'WorkloadWithAssignedConsole'
    $workload.PrivateBytes.Median | Should -Be 55
    $workload.IncompletePrivateSamples | Should -Be 1
  }
}
