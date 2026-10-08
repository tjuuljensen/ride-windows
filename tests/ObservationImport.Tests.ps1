<#
.SYNOPSIS
  Verify evidence import preserves provenance without executing artifacts.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Versioning exception: Repository Pester fixture, no standalone CLI.
#>

BeforeAll {
  $script:importer = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/Import-RideArtifactObservations.ps1'
}

Describe 'Collected observation import' {
  BeforeEach {
    $script:source = Join-Path $TestDrive 'source.json'
    $script:library = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '/library.json')
    $script:record = @{ ObservationId = [guid]::NewGuid().ToString('N'); Sha256 = 'a' * 64; SourceUri = 'https://example.org/app.exe'; AcquisitionKind = 'Download' }
    @{ SchemaVersion = 1; Observations = @($script:record) } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:source
  }

  It 'imports once and preserves existing records on repeated import' {
    $script:record.AuthenticodeSigner = 'CN=Publisher, L=' + [char]0x00CE + 'le-de-France'
    @{ SchemaVersion = 1; Observations = @($script:record) } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:source -Encoding UTF8
    (& $script:importer -Path $script:source -LibraryPath $script:library).Imported | Should -Be 1
    (& $script:importer -Path $script:source -LibraryPath $script:library).Imported | Should -Be 0
    @((Get-Content -LiteralPath $script:library -Raw | ConvertFrom-Json).Observations).Count | Should -Be 1
    (Get-Content -LiteralPath $script:library -Raw -Encoding UTF8 | ConvertFrom-Json).Observations[0].AuthenticodeSigner | Should -BeExactly $script:record.AuthenticodeSigner
  }

  It 'leaves the library intact when an identity has conflicting evidence' {
    $null = & $script:importer -Path $script:source -LibraryPath $script:library
    $before = Get-Content -LiteralPath $script:library -Raw
    $script:record.Sha256 = 'b' * 64
    @{ SchemaVersion = 1; Observations = @($script:record) } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:source
    # Exercise the CLI failure boundary in its own native process. Nested Pester
    # failure handling over WinRM can overflow PowerShell 5.1's call-depth limit.
    $shellName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
    $childCommand = '$ErrorActionPreference = ''Stop''; try { & ''' + $script:importer.Replace("'", "''") + ''' -Path ''' + $script:source.Replace("'", "''") + ''' -LibraryPath ''' + $script:library.Replace("'", "''") + ''' } catch { [Console]::Out.WriteLine($_.Exception.Message); exit 1 }'
    $failureOutput = & (Join-Path $PSHOME $shellName) -NoLogo -NoProfile -ExecutionPolicy Bypass -Command $childCommand | Out-String
    $LASTEXITCODE | Should -Be 1
    $failureOutput | Should -Match 'Conflicting observation ID'
    (Get-Content -LiteralPath $script:library -Raw) | Should -BeExactly $before
  }

  It 'writes neither a directory nor lock during preview' {
    $null = & $script:importer -Path $script:source -LibraryPath $script:library -WhatIf
    Test-Path -LiteralPath (Split-Path -Parent $script:library) | Should -BeFalse
  }

  It 'rejects a member bound to a different archive' {
    $script:record.Contents = @(@{ Sha256 = 'b' * 64; ParentSha256 = 'c' * 64 })
    @{ SchemaVersion = 1; Observations = @($script:record) } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:source
    { & $script:importer -Path $script:source -LibraryPath $script:library } | Should -Throw '*does not match its parent*'
    Test-Path -LiteralPath $script:library | Should -BeFalse
  }
}
