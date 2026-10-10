<#
.SYNOPSIS
  Verify local license review persistence, portability, and read-only discovery.
.DESCRIPTION
  Uses only Pester TestDrive files and catalog data. No network or installer calls.
.EXAMPLE
  Invoke-Pester .\tests\LicenseReviews.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; Pester 5.x.
  Owner: RIDE-Windows maintainers. Repository test fixture; no standalone CLI.
#>


BeforeAll {
  $script:ReviewTool = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/Manage-RideLicenseReviews.ps1'
}

Describe 'Local user/company license reviews' {
  BeforeEach { $script:store = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '/reviews.json') }

  It 'reads unknown reviews and metadata without creating storage' {
    $row = & $script:ReviewTool Get -Id package.7zip -StorePath $script:store
    $row.LicenseReviewStatus | Should -Be 'Unknown'
    $row.LicenseUri | Should -Be 'https://www.7-zip.org/license.txt'
    $row.LicenseReviewedAt | Should -BeNullOrEmpty
    Test-Path -LiteralPath (Split-Path -Parent $script:store) | Should -BeFalse
  }

  It 'previews a review without creating a file, folder, or lock' {
    & $script:ReviewTool Set -Id package.7zip -ReviewedVersion 26.04 -ReviewOwner 'Company A' -LicenseReviewStatus Reviewed -StorePath $script:store -WhatIf
    Test-Path -LiteralPath (Split-Path -Parent $script:store) | Should -BeFalse
  }

  It 'retains exact versions and separate owners and replaces only the selected review' {
    foreach ($selection in @(@('26.04', 'Company A'), @('26.03', 'Company A'), @('26.04', 'Person B'))) {
      & $script:ReviewTool Set -Id package.7zip -ReviewedVersion $selection[0] -ReviewOwner $selection[1] -LicenseReviewStatus NeedsReview -StorePath $script:store | Out-Null
    }
    & $script:ReviewTool Set -Id PACKAGE.7ZIP -ReviewedVersion 26.04 -ReviewOwner 'Company A' -LicenseReviewStatus reviewed -LicenseReviewedAt '2026-10-10T12:00:00+02:00' -DistributionNotes 'Internal installation reviewed.' -StorePath $script:store | Out-Null
    $rows = @(& $script:ReviewTool Get -Id package.7zip -StorePath $script:store)
    $rows.Count | Should -Be 3
    $review = $rows | Where-Object { $_.ReviewOwner -eq 'Company A' -and $_.ReviewedVersion -eq '26.04' }
    $review.LicenseReviewStatus | Should -Be 'Reviewed'
    $review.LicenseReviewedAt | Should -Be '2026-10-10T10:00:00.0000000Z'
    @($rows | Where-Object LicenseReviewStatus -eq 'NeedsReview').Count | Should -Be 2
    $document = Get-Content -LiteralPath $script:store -Raw | ConvertFrom-Json
    $document.SchemaVersion | Should -Be 1
    'LicenseUri' | Should -Not -BeIn $document.Reviews[0].PSObject.Properties.Name
  }

  It 'round trips JSON exports and idempotently merges without losing unrelated reviews' {
    & $script:ReviewTool Set -Id package.7zip -ReviewedVersion 26.04 -ReviewOwner 'Company A' -LicenseReviewStatus Reviewed -StorePath $script:store | Out-Null
    $export = Join-Path $TestDrive 'roundtrip.json'
    & $script:ReviewTool Export -StorePath $script:store -Path $export | Out-Null
    $otherStore = Join-Path $TestDrive 'other/reviews.json'
    & $script:ReviewTool Set -Id package.notepadpp -ReviewedVersion 8.9.8 -ReviewOwner 'Company A' -LicenseReviewStatus Unknown -StorePath $otherStore | Out-Null
    & $script:ReviewTool Import -StorePath $otherStore -Path $export | Out-Null
    & $script:ReviewTool Import -StorePath $otherStore -Path $export | Out-Null
    $document = Get-Content -LiteralPath $otherStore -Raw | ConvertFrom-Json
    $document.Reviews.Count | Should -Be 2
    $document.Reviews.Id | Should -Contain 'package.notepadpp'
    { & $script:ReviewTool Export -StorePath $script:store -Path $export } | Should -Throw '*Force*'
    & $script:ReviewTool Export -StorePath $script:store -Path $export -Force | Out-Null
  }

  It 'rejects conflicting imports without altering existing bytes until Force is selected' {
    & $script:ReviewTool Set -Id package.7zip -ReviewedVersion 26.04 -ReviewOwner 'Company A' -LicenseReviewStatus NeedsReview -StorePath $script:store | Out-Null
    $export = Join-Path $TestDrive 'conflict.json'
    & $script:ReviewTool Export -StorePath $script:store -Path $export | Out-Null
    & $script:ReviewTool Set -Id package.7zip -ReviewedVersion 26.04 -ReviewOwner 'Company A' -LicenseReviewStatus Reviewed -StorePath $script:store | Out-Null
    $before = Get-Content -LiteralPath $script:store -Raw
    { & $script:ReviewTool Import -StorePath $script:store -Path $export } | Should -Throw '*Conflicting imported review*'
    (Get-Content -LiteralPath $script:store -Raw) | Should -BeExactly $before
    & $script:ReviewTool Import -StorePath $script:store -Path $export -Force | Out-Null
    (& $script:ReviewTool Get -Id package.7zip -StorePath $script:store).LicenseReviewStatus | Should -Be 'NeedsReview'
  }

  It 'rejects unsupported schemas and malformed records before changing existing data' {
    & $script:ReviewTool Set -Id package.7zip -ReviewedVersion 26.04 -ReviewOwner 'Company A' -LicenseReviewStatus NeedsReview -StorePath $script:store | Out-Null
    $before = Get-Content -LiteralPath $script:store -Raw
    $inputPath = Join-Path $TestDrive 'invalid.json'
    foreach ($json in @('{"SchemaVersion":2,"Reviews":[]}', '{"SchemaVersion":1,"Reviews":{}}', '{"SchemaVersion":1,"Reviews":[{}]}')) {
      [IO.File]::WriteAllText($inputPath, $json)
      { & $script:ReviewTool Import -StorePath $script:store -Path $inputPath } | Should -Throw
      (Get-Content -LiteralPath $script:store -Raw) | Should -BeExactly $before
    }
    { & $script:ReviewTool Set -Id package.7zip -ReviewedVersion 26.04 -ReviewOwner 'Company A' -LicenseReviewStatus Reviewed -LicenseReviewedAt '2026-10-10' -StorePath $script:store } | Should -Throw '*ISO 8601*'
  }

  It 'preserves retired IDs on import for historical exports' {
    $inputPath = Join-Path $TestDrive 'retired.json'
    [IO.File]::WriteAllText($inputPath, '{"SchemaVersion":1,"Reviews":[{"Id":"package.retired","ReviewedVersion":"1.0","ReviewOwner":"Company A","LicenseReviewStatus":"NeedsReview","DistributionNotes":"Historical","LicenseReviewedAt":null}]}')
    & $script:ReviewTool Import -StorePath $script:store -Path $inputPath | Out-Null
    $row = & $script:ReviewTool Get -StorePath $script:store | Where-Object Id -eq 'package.retired'
    $row.DistributionNotes | Should -Be 'Historical'
    $row.LicenseUri | Should -BeNullOrEmpty
  }

  It 'completes only catalog package/artifact IDs with a case-insensitive prefix' {
    $line = '& "' + $script:ReviewTool + '" Set -Id PACKAGE.7'
    $completion = [Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null)
    $completion.CompletionMatches.CompletionText | Should -Contain 'package.7zip'
    $completion.CompletionMatches.CompletionText | Should -Not -Contain 'windows.show-known-extensions'
    $line = '& "' + $script:ReviewTool + '" -LicenseReviewStatus N'
    $completion = [Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null)
    $completion.CompletionMatches.CompletionText | Should -Contain 'NeedsReview'
  }

  It 'rejects concurrent writers without losing the original store' {
    & $script:ReviewTool Set -Id package.7zip -ReviewedVersion 26.04 -ReviewOwner 'Company A' -LicenseReviewStatus NeedsReview -StorePath $script:store | Out-Null
    $before = Get-Content -LiteralPath $script:store -Raw
    $heldLock = [IO.File]::Open($script:store + '.lock', [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
      { & $script:ReviewTool Set -Id package.7zip -ReviewedVersion 26.04 -ReviewOwner 'Company A' -LicenseReviewStatus Reviewed -StorePath $script:store } | Should -Throw
      (Get-Content -LiteralPath $script:store -Raw) | Should -BeExactly $before
    }
    finally { $heldLock.Dispose() }
  }
}
