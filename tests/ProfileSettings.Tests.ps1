<#
.SYNOPSIS
  Verify profile settings using isolated files and mocked runtime discovery.
.DESCRIPTION
  Exercises encoding preservation, managed-block conflicts, preview, repeat apply,
  bounded recovery, engine snapshots and metadata-only completion. Never modifies
  the developer's profile, Terminal settings, PATH or Windows registry.
.EXAMPLE
  Invoke-Pester .\tests\ProfileSettings.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.7.1 on Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Repository engine; TestDrive. Runtime discovery and identity are mocked.
  Recovery: Pester removes only its own isolated fixtures.
  Author: RIDE-Windows maintainers.
  Version: Repository test fixture; no independent CLI version.
  Changelog: 2026-10-12: Add per-edition profile color lifecycle coverage.
#>


BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-ProfileSettings.psm1') -Global
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogValidation.psm1') -Force
  $script:ColorOperations = @((Get-RideCatalog).Operations | Where-Object Kind -eq ProfileSetting)
}

Describe 'PowerShell profile setting files' {
  BeforeEach {
    $script:ProfileFixture = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + ' redirected [documents]')
    $null = New-Item -Path $script:ProfileFixture -ItemType Directory
    $script:Operation = $script:ColorOperations[0]
    $script:ProfilePath = Join-Path $script:ProfileFixture 'Microsoft.PowerShell_profile.ps1'
    InModuleScope RIDE-ProfileSettings -Parameters @{ Path = $script:ProfilePath } {
      param($Path)
      $script:ProfileFixturePath = $Path
      Mock Resolve-RideProfileSettingTarget {
        [pscustomobject]@{ Available = $true; Path = $script:ProfileFixturePath; OwnerSid = 'S-1-5-21-fixture' }
      }
    }
  }

  It 'has separate optional edition settings with accepted targets and explicit defaults' {
    $script:ColorOperations.Count | Should -Be 2
    foreach ($operation in $script:ColorOperations) {
      $operation.Scope | Should -Be User
      $operation.RequiresAdmin | Should -BeFalse
      $operation.PendingAcceptance | Should -BeFalse
      $operation.SupportedTargets.Count | Should -Be 2
      foreach ($target in @('Windows 11','Windows Server 2025')) {
        $operation.SupportedTargets | Should -Contain $target
        $operation.TargetDefaults[$target].DefaultValue | Should -Be Default
        $operation.TargetDefaults[$target].EffectiveDefault | Should -Match 'No RIDE startup override'
      }
      $operation.BaselineState | Should -Be Default
      $operation.UnsetState | Should -Be Default
      $operation.AdminColorScheme | Should -Be 'Campbell PowerShell'
      $operation.Rollback | Should -Be Exact
    }
    $default = Get-RideProfile -Path (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $default.Operations.Id | Should -Not -Contain $script:Operation.Id
    @(Show-RideCatalog -View 'profile-settings').Count | Should -Be 2
  }

  It 'previews without creating the profile and applies only once' {
    Set-RideProfileSettingState $script:Operation Recommended -WhatIf
    Test-Path -LiteralPath $script:ProfilePath | Should -BeFalse
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    $current = Get-RideProfileSettingState $script:Operation
    $current.State | Should -Be Recommended
    $current.Block | Should -Match '\]11;#012456'
    $current.Block | Should -Match 'WindowsIdentity\]::GetCurrent'
    $current.Block | Should -Match 'IsInRole'
    $current.Block | Should -Not -Match 'ExecutionPolicy|Clear-Host|function prompt|WindowTitle|env:Path'
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    (Get-RideProfileSettingState $script:Operation).FileBase64 | Should -BeExactly $current.FileBase64
  }

  It 'preserves exact original bytes through apply and restore for <Encoding>' -ForEach @(
    @{ Encoding = 'Utf8'; NewLine = "`n" }, @{ Encoding = 'Utf8Bom'; NewLine = "`r`n" },
    @{ Encoding = 'Utf16LE'; NewLine = "`r`n" }, @{ Encoding = 'Utf16BE'; NewLine = "`n" },
    @{ Encoding = 'Ansi'; NewLine = "`n" }
  ) {
    $text = '# caf' + [char]233 + $NewLine + 'function prompt { ''custom> '' }'
    $codec = switch ($Encoding) {
      Utf8 { New-Object Text.UTF8Encoding($false) }
      Utf8Bom { New-Object Text.UTF8Encoding($true) }
      Utf16LE { New-Object Text.UnicodeEncoding($false, $true) }
      Utf16BE { New-Object Text.UnicodeEncoding($true, $true) }
      Ansi { [Text.Encoding]::GetEncoding(1252) }
    }
    [byte[]]$bytes = @($codec.GetPreamble()) + @($codec.GetBytes($text))
    [IO.File]::WriteAllBytes($script:ProfilePath, $bytes)
    $before = Get-RideProfileSettingState $script:Operation
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation $before Recommended | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    Set-RideProfileSettingState $script:Operation Recommended -ExpectedState $before -Confirm:$false
    $after = [IO.File]::ReadAllBytes($script:ProfilePath)
    [Convert]::ToBase64String($after[0..($bytes.Length - 1)]) | Should -BeExactly ([Convert]::ToBase64String($bytes))
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:ProfilePath)) | Should -BeExactly ([Convert]::ToBase64String($bytes))
  }

  It 'uses One Half Dark in normal PowerShell 7 and blue in its admin branch' {
    $operation = $script:ColorOperations | Where-Object ProfileRuntime -eq PowerShell7
    Set-RideProfileSettingState $operation Recommended -Confirm:$false
    $content = [IO.File]::ReadAllText($script:ProfilePath)
    $content | Should -Match '\]11;#282C34'
    $content | Should -Match '\]11;#012456'
    $content | Should -Match '\]4;0;'
    $content | Should -Match '\]12;#FFFFFF'
    $content | Should -Match 'Major -ne 7'
  }

  It 'offers admin-only color handling without emitting a normal-session override' {
    Set-RideProfileSettingState $script:Operation AdminBlue -Confirm:$false
    $content = [IO.File]::ReadAllText($script:ProfilePath)
    $content | Should -Match 'if \(-not \$admin\) \{ return \}'
    $content | Should -Not -Match '\]11;#0C0C0C'
    $content | Should -Match 'IsOutputRedirected|ConsoleHost|WT_SESSION|PSSenderInfo'
    Set-RideProfileSettingState $script:Operation Default -Confirm:$false
    (Get-RideProfileSettingState $script:Operation).State | Should -Be Default
  }

  It 'restores a newly created profile to absence and supports preview and repeated restore' {
    $before = Get-RideProfileSettingState $script:Operation
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation $before Recommended
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    Restore-RideProfileSettingState $script:Operation $snapshot -ValidateOnly
    Restore-RideProfileSettingState $script:Operation $snapshot -WhatIf
    Test-Path -LiteralPath $script:ProfilePath | Should -BeTrue
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
    Test-Path -LiteralPath $script:ProfilePath | Should -BeFalse
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
  }

  It 'recovers original absence when a newly created profile was subsequently unset' {
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation (Get-RideProfileSettingState $script:Operation) Recommended
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    Set-RideProfileSettingState $script:Operation Default -Confirm:$false
    Test-Path -LiteralPath $script:ProfilePath | Should -BeTrue
    Restore-RideProfileSettingState $script:Operation $snapshot -WhatIf
    Test-Path -LiteralPath $script:ProfilePath | Should -BeTrue
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
    Test-Path -LiteralPath $script:ProfilePath | Should -BeFalse
  }

  It 'preserves appended unrelated content instead of deleting a RIDE-created file on restore' {
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation (Get-RideProfileSettingState $script:Operation) Recommended
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    [IO.File]::AppendAllText($script:ProfilePath, "# keep this edit`n")
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
    [IO.File]::ReadAllText($script:ProfilePath) | Should -BeExactly "# keep this edit`n"
  }

  It 'preserves edits before and after the block and changes only the chosen setting' {
    [IO.File]::WriteAllText($script:ProfilePath, "# before`n")
    Set-RideProfileSettingState $script:Operation AdminBlue -Confirm:$false
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation (Get-RideProfileSettingState $script:Operation) Recommended
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    $content = [IO.File]::ReadAllText($script:ProfilePath).Replace('# before', '# before edited')
    [IO.File]::WriteAllText($script:ProfilePath, ($content + "# after`n"))
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
    $current = Get-RideProfileSettingState $script:Operation
    $current.State | Should -Be AdminBlue
    [IO.File]::ReadAllText($script:ProfilePath) | Should -Match '# before edited'
    [IO.File]::ReadAllText($script:ProfilePath) | Should -Match '# after'
  }

  It 'restores an unset block after append-only edits but refuses a changed insertion boundary' {
    [IO.File]::WriteAllText($script:ProfilePath, "# user`n")
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation (Get-RideProfileSettingState $script:Operation) Default
    Set-RideProfileSettingState $script:Operation Default -Confirm:$false
    [IO.File]::AppendAllText($script:ProfilePath, "# later`n")
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
    (Get-RideProfileSettingState $script:Operation).State | Should -Be Recommended
    Set-RideProfileSettingState $script:Operation Default -Confirm:$false
    [IO.File]::WriteAllText($script:ProfilePath, "# changed user`n")
    { Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false } | Should -Throw '*changed around*'
    [IO.File]::ReadAllText($script:ProfilePath) | Should -BeExactly "# changed user`n"
  }

  It 'restores an unset block into an originally empty file with later appended content' {
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation (Get-RideProfileSettingState $script:Operation) Default
    Set-RideProfileSettingState $script:Operation Default -Confirm:$false
    [IO.File]::AppendAllText($script:ProfilePath, '# appended')
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
    (Get-RideProfileSettingState $script:Operation).State | Should -Be Recommended
    [IO.File]::ReadAllText($script:ProfilePath) | Should -Match '# appended$'
  }

  It 'rejects edited blocks and duplicate markers before mutation' {
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    $content = [IO.File]::ReadAllText($script:ProfilePath)
    [IO.File]::WriteAllText($script:ProfilePath, $content.Replace('#012456', '#123456'))
    { Set-RideProfileSettingState $script:Operation Default -Confirm:$false } | Should -Throw '*block was modified*'
    [IO.File]::WriteAllText($script:ProfilePath, ($content + $content))
    { Get-RideProfileSettingState $script:Operation } | Should -Throw '*Ambiguous*'
  }

  It 'rejects markers embedded in a here-string instead of editing user code' {
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    $content = [IO.File]::ReadAllText($script:ProfilePath)
    [IO.File]::WriteAllText($script:ProfilePath, ("`$userText = @'`n" + $content + "'@`n"))
    { Get-RideProfileSettingState $script:Operation } | Should -Throw '*embedded*'
  }

  It 'refuses syntactically invalid profiles, oversized files and directories' {
    [IO.File]::WriteAllText($script:ProfilePath, 'function broken {')
    { Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false } | Should -Throw '*syntax errors*'
    [IO.File]::WriteAllText($script:ProfilePath, ('x' * (1MB + 1)))
    { Get-RideProfileSettingState $script:Operation } | Should -Throw '*limit*'
    [IO.File]::Delete($script:ProfilePath)
    $null = New-Item -Path $script:ProfilePath -ItemType Directory
    { Get-RideProfileSettingState $script:Operation } | Should -Throw '*directory*'
  }

  It 'rejects changes after snapshot capture and changes between inspection and the locked write' {
    [IO.File]::WriteAllText($script:ProfilePath, '# before')
    $before = Get-RideProfileSettingState $script:Operation
    $wrongOwner = $before.PSObject.Copy(); $wrongOwner.OwnerSid = 'another-user'
    { Set-RideProfileSettingState $script:Operation Recommended -ExpectedState $wrongOwner -Confirm:$false } | Should -Throw '*identity or content changed*'
    [IO.File]::WriteAllText($script:ProfilePath, '# edited')
    { Set-RideProfileSettingState $script:Operation Recommended -ExpectedState $before -Confirm:$false } | Should -Throw '*after snapshot capture*'
    InModuleScope RIDE-ProfileSettings -Parameters @{ Current = $before } {
      param($Current)
      { Write-RideProfileSettingFile $Current ([byte[]]@(65)) } | Should -Throw '*after inspection*'
    }
    [IO.File]::ReadAllText($script:ProfilePath) | Should -BeExactly '# edited'
  }

  It 'refuses saved identity drift for <Field>' -ForEach @(
    @{ Field = 'OwnerSid'; Value = 'another-user' }, @{ Field = 'Path'; Value = 'C:\other\Microsoft.PowerShell_profile.ps1' },
    @{ Field = 'Runtime'; Value = 'another-runtime' }, @{ Field = 'SnapshotVersion'; Value = 2 }
  ) {
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation (Get-RideProfileSettingState $script:Operation) Recommended
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    $snapshot.$Field = $Value
    { Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false } | Should -Throw '*mismatch*'
    (Get-RideProfileSettingState $script:Operation).State | Should -Be Recommended
  }

  It 'reports a missing optional runtime without creating any file' {
    InModuleScope RIDE-ProfileSettings -Parameters @{ Operation = $script:Operation } {
      param($Operation)
      Mock Resolve-RideProfileSettingTarget { [pscustomobject]@{ Available = $false; Reason = 'not installed'; Path = $null } }
      (Get-RideProfileSettingState $Operation).Available | Should -BeFalse
      { Set-RideProfileSettingState $Operation Recommended -Confirm:$false } | Should -Throw '*unavailable*'
    }
    Test-Path -LiteralPath $script:ProfilePath | Should -BeFalse
  }

  It 'preserves another managed setting in the same file during unset and restore' {
    $other = $script:Operation.Clone(); $other.Id = 'powershell.fixture-other-setting'
    Set-RideProfileSettingState $other AdminBlue -Confirm:$false
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation (Get-RideProfileSettingState $script:Operation) Recommended
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    (Get-RideProfileSettingState $other).State | Should -Be AdminBlue
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
    (Get-RideProfileSettingState $other).State | Should -Be AdminBlue
    (Get-RideProfileSettingState $script:Operation).State | Should -Be Default
  }

  It 'refuses reparse ancestors before reading any profile bytes' {
    InModuleScope RIDE-ProfileSettings -Parameters @{ Operation = $script:Operation } {
      param($Operation)
      Mock Test-Path { $true }
      Mock Get-Item { [pscustomobject]@{ PSIsContainer = $false; Attributes = [IO.FileAttributes]::ReparsePoint } }
      Mock Get-RideProfileReparseTag { [Convert]::ToUInt32('A000000C', 16) }
      { Get-RideProfileSettingState $Operation } | Should -Throw '*reparse point*'
    }
  }

  It 'permits known cloud placeholder tags while rejecting unknown reparse tags' {
    InModuleScope RIDE-ProfileSettings -Parameters @{ Path = $script:ProfilePath } {
      param($Path)
      Mock Test-Path { $true }
      Mock Get-Item { [pscustomobject]@{ PSIsContainer = $false; Attributes = [IO.FileAttributes]::ReparsePoint } }
      Mock Get-RideProfileReparseTag { [Convert]::ToUInt32('9000601A', 16) }
      { Assert-RideProfilePath $Path } | Should -Not -Throw
      Mock Get-RideProfileReparseTag { 1234 }
      { Assert-RideProfilePath $Path } | Should -Throw '*unknown reparse point*'
    }
  }

  It 'rejects inconsistent snapshot bytes before restoring' {
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation (Get-RideProfileSettingState $script:Operation) Recommended
    Set-RideProfileSettingState $script:Operation Recommended -Confirm:$false
    $snapshot.ExpectedFileBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('# unrelated'))
    { Restore-RideProfileSettingState $script:Operation $snapshot -ValidateOnly } | Should -Throw '*snapshot content*'
    (Get-RideProfileSettingState $script:Operation).State | Should -Be Recommended
  }

  It 'keeps a recovery snapshot usable after the writer fails before changing anything' {
    $snapshot = Get-RideProfileSettingSnapshot $script:Operation (Get-RideProfileSettingState $script:Operation) Recommended
    Restore-RideProfileSettingState $script:Operation $snapshot -Confirm:$false
    Test-Path -LiteralPath $script:ProfilePath | Should -BeFalse
  }
}

Describe 'Profile settings engine and discovery' {
  BeforeEach {
    $script:EngineProfilePath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '-profile.ps1')
    $script:FixtureOperation = $script:ColorOperations[0].Clone()
    $script:FixtureOperation.PendingAcceptance = $false
    $script:FixtureOperation.SupportedTargets = @('Windows 11')
    $script:FixtureOperation.TargetDefaults = @{ 'Windows 11' = @{ DefaultValue = 'Default'; EffectiveDefault = 'Configured Terminal appearance; no RIDE override' } }
    InModuleScope RIDE-ProfileSettings -Parameters @{ Path = $script:EngineProfilePath } {
      param($Path)
      $script:ProfileFixturePath = $Path
      Mock Resolve-RideProfileSettingTarget { [pscustomobject]@{ Available = $true; Path = $script:ProfileFixturePath; OwnerSid = 'fixture-user' } }
    }
    InModuleScope RIDE.Engine -Parameters @{ Operation = $script:FixtureOperation; StateRoot = (Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '-state')) } {
      param($Operation, $StateRoot)
      $script:ProfileTestCatalog = @{ SchemaVersion = 1; Operations = @($Operation); Groups = @() }
      $script:ProfileTestStateRoot = $StateRoot
      Mock Get-RideCatalog { $script:ProfileTestCatalog }
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $false }
      Mock Get-RideStateRoot { $script:ProfileTestStateRoot }
    }
  }

  It 'plans set, unset and baseline from declared metadata and completes states read-only' {
    $id = $script:FixtureOperation.Id
    @(Get-RideSingleOperationPlan $id -Action Set -State Baseline)[0].State | Should -Be Default
    @(Get-RideSingleOperationPlan $id -Action Unset)[0].State | Should -Be Default
    { Get-RideSingleOperationPlan $id -Action Set -State Invalid } | Should -Throw '*not supported*'
    Mock Get-RideCurrentState -ModuleName RIDE.Engine { throw 'completion must not inspect profiles' }
    foreach ($line in @('.\ride.ps1 set powershell.windows-powershell51-terminal-colors ', '.\ride.ps1 set powershell.windows-powershell51-terminal-colors -State ')) {
      $matches = (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText
      foreach ($value in @('Recommended', 'AdminBlue', 'Default', 'Baseline')) { $matches | Should -Contain $value }
    }
    Should -Invoke Get-RideCurrentState -ModuleName RIDE.Engine -Times 0 -Exactly
  }

  It 'shows configuration and effective desired values instead of claiming to observe colors' {
    $shown = Show-RideOperation $script:FixtureOperation.Id | Out-String -Width 4096
    $shown | Should -Match 'CurrentState\s+: Default'
    $shown | Should -Match 'BaselineValue\s+: Default'
    $shown | Should -Match 'startup configuration'
    $plan = @(Get-RideSingleOperationPlan $script:FixtureOperation.Id -Action Set -State Recommended)
    $display = Show-RidePlan $plan | Out-String -Width 4096
    $display | Should -Match 'Normal: Campbell; elevated: Campbell PowerShell'
    $status = @(Get-RideStatus -View 'profile-settings')[0]
    $status.CurrentValueType | Should -Be 'PowerShell startup profile setting'
    $status.DefaultValue | Should -Be Default
    $status.MatchesDefault | Should -BeTrue
  }

  It 'previews, records versioned recovery, repeats and restores through the engine' {
    $plan = @(Get-RideSingleOperationPlan $script:FixtureOperation.Id -Action Set -State Recommended)
    Invoke-RidePlan $plan -WhatIf -Confirm:$false | Out-Null
    Test-Path -LiteralPath $script:EngineProfilePath | Should -BeFalse
    $output = @(Invoke-RidePlan $plan -Confirm:$false)
    $runId = ($output | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
    $runId | Should -Match '^[0-9a-f]{32}$'
    InModuleScope RIDE.Engine -Parameters @{ RunId = $runId; Id = $script:FixtureOperation.Id } {
      param($RunId, $Id)
      $record = Get-Content -LiteralPath (Join-Path $script:ProfileTestStateRoot "$RunId/$Id.json") -Raw | ConvertFrom-Json
      $record.Kind | Should -Be ProfileSetting
      $record.Snapshot.SnapshotVersion | Should -Be 1
      $record.Snapshot.FileExists | Should -BeFalse
      $record.Snapshot.ExpectedBlock | Should -Match '\]11;#012456'
    }
    @(Invoke-RidePlan $plan -Confirm:$false) | Should -Contain 'No changes were needed; no state record was created.'
    Restore-RideRun $runId -WhatIf -Confirm:$false | Out-Null
    Test-Path -LiteralPath $script:EngineProfilePath | Should -BeTrue
    Restore-RideRun $runId -Confirm:$false | Out-Null
    Test-Path -LiteralPath $script:EngineProfilePath | Should -BeFalse
  }

  It 'restores an unset operation to its previous managed block' {
    Set-RideProfileSettingState $script:FixtureOperation AdminBlue -Confirm:$false
    $output = @(Invoke-RidePlan @(Get-RideSingleOperationPlan $script:FixtureOperation.Id -Action Unset) -Confirm:$false)
    $runId = ($output | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
    (Get-RideProfileSettingState $script:FixtureOperation).State | Should -Be Default
    Restore-RideRun $runId -Confirm:$false | Out-Null
    (Get-RideProfileSettingState $script:FixtureOperation).State | Should -Be AdminBlue
  }

  It 'reports partial failure and keeps an original snapshot for recovery' {
    InModuleScope RIDE.Engine {
      Mock Set-RideProfileSettingState { throw 'simulated profile writer failure' }
      $plan = @(Get-RideSingleOperationPlan $script:ProfileTestCatalog.Operations[0].Id -Action Set -State Recommended)
      { Invoke-RidePlan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*simulated profile writer failure*'
      $file = Get-ChildItem -LiteralPath $script:ProfileTestStateRoot -Recurse -Filter 'powershell.*.json' | Select-Object -First 1
      $record = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
      $record.Snapshot.FileExists | Should -BeFalse
      Restore-RideRun $record.RunId -Confirm:$false | Out-Null
    }
  }

  It 'blocks application to a candidate target until integration acceptance is recorded' {
    InModuleScope RIDE.Engine -Parameters @{ Operation = $script:ColorOperations[0] } {
      param($Operation)
      $Operation = $Operation.Clone()
      $Operation.SupportedTargets = @(); $Operation.PendingAcceptance = $true
      $Operation.CandidateTargets = @('Windows 11','Windows Server 2025')
      $plan = @([pscustomobject]@{ Operation = $Operation; State = 'Recommended' })
      { Invoke-RidePlan $plan -WhatIf -Confirm:$false } | Should -Throw '*does not support*'
    }
    Test-Path -LiteralPath $script:EngineProfilePath | Should -BeFalse
  }

  It 'rejects missing removal states, wrong scope and unknown color presets in metadata' {
    $invalid = $script:ColorOperations[0].Clone()
    $invalid.UnsetState = 'Unknown'
    $invalid.Scope = 'Machine'
    $invalid.NormalColorScheme = 'Unknown'
    $errors = @(Get-RideCatalogValidationErrors -Catalog @{ SchemaVersion = 1; Operations = @($invalid); Groups = @() })
    $errors -join ';' | Should -Match 'user-scoped handler'
    $errors -join ';' | Should -Match 'explicit removal and baseline'
    $errors -join ';' | Should -Match 'reviewed color schemes'
  }
}

Describe 'Bounded profile runtime discovery' {
  It 'accepts a successful identity-checked query with first-use stderr diagnostics' {
    InModuleScope RIDE-ProfileSettings -Parameters @{ Operation = $script:ColorOperations[0]; Path = (Join-Path $TestDrive 'Microsoft.PowerShell_profile.ps1') } {
      param($Operation, $Path)
      $result = @{ Path = $Path; Major = 5; Minor = 1; Edition = 'Desktop'; HostName = 'ConsoleHost'; OwnerSid = 'fixture-user' } | ConvertTo-Json -Compress
      $script:FakeProfileProcess = [pscustomobject]@{
        StartInfo = $null; ExitCode = 0
        StandardOutput = [IO.StringReader]::new($result)
        StandardError = [IO.StringReader]::new('Preparing modules for first use')
      }
      $script:FakeProfileProcess | Add-Member ScriptMethod Start { $true }
      $script:FakeProfileProcess | Add-Member ScriptMethod WaitForExit { param($Timeout) $Timeout | Should -Be 30000; $true }
      $script:FakeProfileProcess | Add-Member ScriptMethod Dispose { }
      Mock New-Object { $script:FakeProfileProcess } -ParameterFilter { $TypeName -eq 'Diagnostics.Process' }
      Mock Get-RideProfileRuntimeExecutable { 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }
      Mock Get-RideProfileOwnerSid { 'fixture-user' }
      $target = Resolve-RideProfileSettingTarget $Operation
      $target.Available | Should -BeTrue
      $target.Path | Should -Be $Path
      $script:FakeProfileProcess.StartInfo.Arguments | Should -Match '-NoProfile -NonInteractive -EncodedCommand'
      $script:FakeProfileProcess.StartInfo.Arguments | Should -Not -Match 'ExecutionPolicy'
      $script:FakeProfileProcess.ExitCode = 1
      { Resolve-RideProfileSettingTarget $Operation } | Should -Throw '*discovery failed*'
    }
  }
}
