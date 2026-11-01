<#
.SYNOPSIS
  Verify the Windows adapter is pinned to shared RIDE behavior scenarios.
.DESCRIPTION
  Checks scenario revision, canonical contract bytes and mapped Windows Pester
  coverage. Does not run live handlers, registry changes, installers or VMs.
.EXAMPLE
  Invoke-Pester ./tests/BehaviorContract.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Version: repository test fixture. Changelog: 2026-11-01: Add ALIGN-05 pinned scenarios.
#>
Describe 'Pinned shared behavior scenarios' {
  BeforeAll {
    $script:ScenarioRevision = '1.0.0'
    $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
    $script:ScenarioPath = Join-Path $script:RepositoryRoot 'docs/models/behavior-scenarios.json'
    $script:ContractPath = Join-Path $script:RepositoryRoot 'docs/models/ride-behavior-contract.md'
    $script:ReferencePath = Join-Path $script:RepositoryRoot 'docs/models/ride-behavior-contract-ref.json'
    $script:AdapterMapPath = Join-Path $script:RepositoryRoot 'tests/fixtures/behavior-scenario-windows-adapter.json'
    $script:DifferenceRegisterPath = Join-Path $script:RepositoryRoot 'docs/models/capability-differences.json'
    $script:ScenarioSet = Get-Content -LiteralPath $script:ScenarioPath -Raw | ConvertFrom-Json -ErrorAction Stop
    $script:ContractReference = Get-Content -LiteralPath $script:ReferencePath -Raw | ConvertFrom-Json -ErrorAction Stop
    $script:AdapterMap = Get-Content -LiteralPath $script:AdapterMapPath -Raw | ConvertFrom-Json -ErrorAction Stop
    $script:DifferenceRegister = Get-Content -LiteralPath $script:DifferenceRegisterPath -Raw | ConvertFrom-Json -ErrorAction Stop

    $script:ValidateBehaviorScenarioEnvelope = {
      param(
        [Parameter(Mandatory)][psobject] $ScenarioSet,
        [Parameter(Mandatory)][psobject] $ContractReference,
        [Parameter(Mandatory)][string] $ContractPath,
        [Parameter(Mandatory)][string] $ExpectedScenarioRevision
      )

      if ($ScenarioSet.schemaVersion -ne 1) { throw "Unsupported behavior-scenario schema '$($ScenarioSet.schemaVersion)' (expected 1)." }
      if ($ScenarioSet.scenarioRevision -cne $ExpectedScenarioRevision) { throw "Behavior-scenario revision '$($ScenarioSet.scenarioRevision)' does not match pinned revision '$ExpectedScenarioRevision'." }
      if ($ScenarioSet.contractVersion -cne $ContractReference.contractVersion) { throw 'Behavior-scenario contract version does not match the consumer reference.' }
      if ($ScenarioSet.contractSha256 -cne $ContractReference.sha256) { throw 'Behavior-scenario contract digest does not match the consumer reference.' }
      $actualDigest = (Get-FileHash -LiteralPath $ContractPath -Algorithm SHA256 -ErrorAction Stop).Hash
      if ($actualDigest -cne $ContractReference.sha256) { throw 'Canonical behavior contract bytes do not match the pinned consumer digest.' }
      if (@($ScenarioSet.scenarios).Count -eq 0) { throw 'The behavior-scenario set is empty.' }
      $ids = @($ScenarioSet.scenarios | ForEach-Object { [string]$_.id })
      if (@($ids | Sort-Object -Unique).Count -ne $ids.Count) { throw 'Behavior-scenario IDs must be unique.' }
    }
  }

  It 'matches the scenario revision and canonical contract digest pinned by this consumer' {
    { & $script:ValidateBehaviorScenarioEnvelope -ScenarioSet $script:ScenarioSet -ContractReference $script:ContractReference -ContractPath $script:ContractPath -ExpectedScenarioRevision $script:ScenarioRevision } | Should -Not -Throw
  }

  It 'rejects a seeded scenario-revision mismatch' {
    $seededMismatch = $script:ScenarioSet | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    $seededMismatch.scenarioRevision = '9.9.9'
    { & $script:ValidateBehaviorScenarioEnvelope -ScenarioSet $seededMismatch -ContractReference $script:ContractReference -ContractPath $script:ContractPath -ExpectedScenarioRevision $script:ScenarioRevision } | Should -Throw '*does not match pinned revision*'
  }

  It 'maps every shared scenario to a named Windows Pester case without platform-specific fields in shared data' {
    $sharedScenarios = @($script:ScenarioSet.scenarios)
    $mappings = @($script:AdapterMap.mappings)
    $script:AdapterMap.scenarioRevision | Should -BeExactly $script:ScenarioRevision
    @($mappings | ForEach-Object scenarioId | Sort-Object -Unique).Count | Should -Be $sharedScenarios.Count
    foreach ($scenario in $script:ScenarioSet.scenarios) {
      $scenario.id | Should -Not -BeNullOrEmpty
      $scenario.rules | Should -Not -BeNullOrEmpty
      $scenario.expected | Should -Not -BeNullOrEmpty
      @($scenario.PSObject.Properties.Name) | Should -Not -Contain 'windowsAdapter'
      $mapping = @($mappings | Where-Object scenarioId -CEQ $scenario.id)
      $mapping.Count | Should -Be 1
      $adapterPath = Join-Path $script:RepositoryRoot $mapping[0].file
      Test-Path -LiteralPath $adapterPath -PathType Leaf | Should -BeTrue
      $adapterContent = Get-Content -LiteralPath $adapterPath -Raw
      $title = [regex]::Escape([string]$mapping[0].testTitle)
      $adapterContent | Should -Match "(?m)^\s*It '$title'"
    }
  }

  It 'requires an owner, rule, evidence, linked work and trigger for every capability disposition' {
    $register = $script:DifferenceRegister
    $register.schemaVersion | Should -Be 1
    $register.contractVersion | Should -BeExactly $script:ContractReference.contractVersion
    $register.reviewedSources.rideWindows.commit | Should -Not -BeNullOrEmpty
    $register.reviewedSources.rideFedora.commit | Should -Not -BeNullOrEmpty
    $entries = @($register.entries)
    $entries.Count | Should -BeGreaterThan 0
    @($entries.id | Sort-Object -Unique).Count | Should -Be $entries.Count
    foreach ($entry in $entries) {
      $entry.owner | Should -Not -BeNullOrEmpty
      $entry.reason | Should -Not -BeNullOrEmpty
      $entry.ruleIds | Should -Not -BeNullOrEmpty
      $entry.evidence | Should -Not -BeNullOrEmpty
      @($entry.PSObject.Properties.Name) | Should -Contain 'linkedWork'
      $entry.reviewRemovalTrigger | Should -Not -BeNullOrEmpty
      $entry.disposition | Should -BeIn @('aligned', 'temporary-gap', 'permanent-platform-difference')
      $entry.decisionStatus | Should -BeIn @('source-reviewed', 'open', 'proposed-owner-review')
    }
  }
}
