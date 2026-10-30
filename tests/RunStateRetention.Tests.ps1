<#
.SYNOPSIS
  Tests guarded cleanup of expired completed RIDE run records.
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
#>
BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
}

Describe 'RIDE run-state retention' {
  BeforeEach {
    $script:RetentionRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $script:RetentionRoot -Force
    Mock Get-RideStateRoot -ModuleName RIDE.Engine { Join-Path $script:RetentionRoot $Scope }
    Mock Test-RideAdministrator -ModuleName RIDE.Engine { $true }
  }

  It 'previews only old fully completed run records and preserves them in WhatIf' {
    $runId = [guid]::NewGuid().ToString('N')
    $runDirectory = Join-Path (Join-Path $script:RetentionRoot 'User') $runId
    $null = New-Item -ItemType Directory -Path $runDirectory -Force
    [ordered]@{
      SchemaVersion = 1
      RunId = $runId
      Scopes = @('User')
      OperationIds = @('test.user-setting')
      OperationProgress = @([ordered]@{ OperationId = 'test.user-setting'; Status = 'Completed' })
      CreatedUtc = [DateTime]::UtcNow.AddDays(-400).ToString('o')
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runDirectory '_manifest.json') -Encoding UTF8
    $null = New-Item -ItemType Directory -Path (Join-Path $runDirectory 'snapshot.files') -Force
    [IO.File]::WriteAllText((Join-Path $runDirectory 'snapshot.files/backup.bin'), 'fixture')

    $result = @(Remove-RideOldRunRecords -OlderThanDays 365 -Scope User -WhatIf -Confirm:$false)

    $result.Count | Should -Be 1
    $result[0].Status | Should -BeExactly 'Previewed'
    $result[0].RunId | Should -BeExactly $runId
    (Test-Path -LiteralPath $runDirectory) | Should -BeTrue
  }

  It 'removes an expired completed run only after ShouldProcess approves' {
    $runId = [guid]::NewGuid().ToString('N')
    $runDirectory = Join-Path (Join-Path $script:RetentionRoot 'User') $runId
    $null = New-Item -ItemType Directory -Path $runDirectory -Force
    [ordered]@{
      SchemaVersion = 1
      RunId = $runId
      Scopes = @('User')
      OperationIds = @('test.user-setting')
      OperationProgress = @([ordered]@{ OperationId = 'test.user-setting'; Status = 'AlreadyDesired' })
      CreatedUtc = [DateTime]::UtcNow.AddDays(-400).ToString('o')
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runDirectory '_manifest.json') -Encoding UTF8

    $result = @(Remove-RideOldRunRecords -OlderThanDays 365 -Scope User -Confirm:$false)

    $result[0].Status | Should -BeExactly 'Removed'
    (Test-Path -LiteralPath $runDirectory) | Should -BeFalse
  }

  It 'retains recent, failed and unfinished run records' {
    $records = @(
      @{ Age = 40; Status = 'Completed'; Expected = 'Younger than retention period' },
      @{ Age = 400; Status = 'Failed'; Expected = 'Contains failed or unfinished operations' },
      @{ Age = 400; Status = 'SnapshotSaved'; Expected = 'Contains failed or unfinished operations' }
    )
    foreach ($record in $records) {
      $runId = [guid]::NewGuid().ToString('N')
      $runDirectory = Join-Path (Join-Path $script:RetentionRoot 'User') $runId
      $null = New-Item -ItemType Directory -Path $runDirectory -Force
      [ordered]@{
        SchemaVersion = 1
        RunId = $runId
        Scopes = @('User')
        OperationIds = @('test.user-setting')
        OperationProgress = @([ordered]@{ OperationId = 'test.user-setting'; Status = $record.Status })
        CreatedUtc = [DateTime]::UtcNow.AddDays(-$record.Age).ToString('o')
      } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runDirectory '_manifest.json') -Encoding UTF8
    }

    $results = @(Remove-RideOldRunRecords -OlderThanDays 365 -Scope User -WhatIf -Confirm:$false)

    $results.Count | Should -Be 3
    @($results | Where-Object Status -ne 'Retained').Count | Should -Be 0
    @($results | Where-Object Reason -eq 'Younger than retention period').Count | Should -Be 1
    @($results | Where-Object Reason -eq 'Contains failed or unfinished operations').Count | Should -Be 2
  }

  It 'requires elevation before inspecting machine run records' {
    Mock Test-RideAdministrator -ModuleName RIDE.Engine { $false }

    { Remove-RideOldRunRecords -Scope Machine -WhatIf } | Should -Throw '*elevated PowerShell session*'
    Should -Invoke Get-RideStateRoot -ModuleName RIDE.Engine -Exactly 0
  }

  It 'retains run directories with malformed manifests' {
    $runId = [guid]::NewGuid().ToString('N')
    $runDirectory = Join-Path (Join-Path $script:RetentionRoot 'User') $runId
    $null = New-Item -ItemType Directory -Path $runDirectory -Force
    [IO.File]::WriteAllText((Join-Path $runDirectory '_manifest.json'), '{ invalid json')

    $result = @(Remove-RideOldRunRecords -OlderThanDays 365 -Scope User -WhatIf -Confirm:$false)

    $result.Count | Should -Be 1
    $result[0].Status | Should -BeExactly 'Retained'
    $result[0].Reason | Should -BeExactly 'Manifest is unreadable or invalid JSON'
    (Test-Path -LiteralPath $runDirectory) | Should -BeTrue
  }
}
