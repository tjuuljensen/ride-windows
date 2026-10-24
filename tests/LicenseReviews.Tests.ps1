<#
.SYNOPSIS
  Verify local license review persistence, portability, and read-only discovery.
.DESCRIPTION
  Uses unique workspace-local temporary stores, Pester TestDrive imports and catalog data.
  No network or installer calls.
.EXAMPLE
  Invoke-Pester .\tests\LicenseReviews.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; Pester 5.x.
  Owner: RIDE-Windows maintainers. Repository test fixture; no standalone CLI.
#>


BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  $script:ReviewTool = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/Manage-RideLicenseReviews.ps1'
  $script:ReviewTempRoot = Join-Path $script:RepositoryRoot '.local/pester-license-review'
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  $script:ReviewCatalog = Get-RideCatalog
}

Describe 'Local user/company license reviews' {
  BeforeEach {
    $script:reviewTestRoot = Join-Path $script:ReviewTempRoot ([guid]::NewGuid().ToString('N'))
    $script:store = Join-Path $script:reviewTestRoot 'reviews.json'
  }
  AfterEach {
    if (Test-Path -LiteralPath $script:reviewTestRoot -PathType Container) {
      $root = [IO.Path]::GetFullPath($script:reviewTestRoot).TrimEnd('\')
      $tempRoot = [IO.Path]::GetFullPath($script:ReviewTempRoot).TrimEnd('\')
      if ([IO.Path]::GetDirectoryName($root) -ine $tempRoot -or
          (Split-Path -Leaf $root) -notmatch '^[a-f0-9]{32}$') { throw 'Refusing license-test cleanup outside its unique workspace-local directory.' }
      $entries = @(Get-ChildItem -LiteralPath $root -Force)
      foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or [IO.Path]::GetDirectoryName($entry.FullName) -ine $root) { throw 'Unexpected nested license-test output; preserve it for inspection.' }
        Remove-Item -LiteralPath $entry.FullName -Force
      }
      Remove-Item -LiteralPath $root -Force
    }
  }

  It 'reads unknown reviews and metadata without creating storage' {
    $row = & $script:ReviewTool Get -Id package.7zip -StorePath $script:store
    $row.LicenseReviewStatus | Should -Be 'Unknown'
    $row.LicenseUri | Should -Be 'https://www.7-zip.org/license.txt'
    $row.LicenseReviewedAt | Should -BeNullOrEmpty
    Test-Path -LiteralPath (Split-Path -Parent $script:store) | Should -BeFalse
  }

  It 'keeps NeedsReview records informational across pending package install planning' {
    foreach ($candidate in @(
      @{ Id='package.phoenix-protector'; Version='1.7.1' },
      @{ Id='package.ntcore-4gb-patch'; Version='1.0.0.1' },
      @{ Id='package.mitec-uuid-generator'; Version='1.0.0' },
      @{ Id='package.mitec-sqlite-query'; Version='3.2.0' },
      @{ Id='package.mitec-system-information'; Version='16.0.0' },
      @{ Id='package.mitec-tapi-monitor'; Version='1.2.0' },
      @{ Id='package.mitec-windows-file-analyzer'; Version='2.10.0' },
      @{ Id='package.mitec-icon-explorer'; Version='5.3.0' },
      @{ Id='package.mitec-ole-com-explorer'; Version='1.4.0.0' },
      @{ Id='package.mitec-windows-registry-recovery'; Version='3.1.3' },
      @{ Id='package.mitec-smbios-explorer'; Version='1.8.0' },
      @{ Id='package.mitec-dfm-editor'; Version='8.3.1.0' },
      @{ Id='package.mitec-dfm-editor'; Version='8.4.0.0' },
      @{ Id='package.mitec-exe-explorer'; Version='3.7.5' },
      @{ Id='package.mitec-hexedit'; Version='7.1.0' },
      @{ Id='package.mitec-mail-viewer'; Version='2.5.1.0' },
      @{ Id='package.mitec-email-history-browser'; Version='1.2.0' },
      @{ Id='package.mitec-internet-history-browser'; Version='2.5.0' },
      @{ Id='package.mitec-instant-messaging-history-browser'; Version='1.2.1' },
      @{ Id='package.tmog'; Version='1.0.1' },
      @{ Id='package.wireshark'; Version='4.6.9' }
    )) {
      & $script:ReviewTool Set -Id $candidate.Id -ReviewedVersion $candidate.Version -ReviewOwner 'Company A' -LicenseReviewStatus NeedsReview -StorePath $script:store | Out-Null
      $review = @(& $script:ReviewTool Get -Id $candidate.Id -StorePath $script:store | Where-Object { $_.ReviewedVersion -ceq $candidate.Version })
      $review.Count | Should -Be 1
      $review = $review[0]
      $review.LicenseReviewStatus | Should -Be 'NeedsReview'
      $review.ReviewedVersion | Should -BeExactly $candidate.Version

      $plan = @(Get-RideSingleOperationPlan -Id $candidate.Id -Action Install)
      $plan.Count | Should -Be 1
      $plan[0].Operation.Kind | Should -Be 'Package'
      $plan[0].State | Should -Be 'Present'
      $plan[0].Operation.PendingAcceptance | Should -BeTrue
    }
  }

  It 'keeps every pending package install plan available when a local NeedsReview record exists' {
    $pendingPackages=@($script:ReviewCatalog.Operations|Where-Object {$_.Kind -ceq 'Package' -and $_.PendingAcceptance -ceq $true})
    $pendingPackages.Count|Should -BeGreaterThan 0
    foreach($operation in $pendingPackages){
      & $script:ReviewTool Set -Id $operation.Id -ReviewedVersion $operation.PackageVersion -ReviewOwner 'Planning regression' -LicenseReviewStatus NeedsReview -StorePath $script:store | Out-Null
      $review=& $script:ReviewTool Get -Id $operation.Id -StorePath $script:store
      $review.LicenseReviewStatus|Should -BeExactly 'NeedsReview'
      $review.ReviewedVersion|Should -BeExactly $operation.PackageVersion
      $plan=@(Get-RideSingleOperationPlan -Id $operation.Id -Action Install)
      @($plan|Where-Object {$_.Operation.Id -ceq $operation.Id}).Count|Should -Be 1
      @($plan|Where-Object {$_.Operation.Id -ceq $operation.Id})[0].State|Should -BeExactly 'Present'
      @($plan|Where-Object {$_.Operation.Id -ceq $operation.Id})[0].Operation.PendingAcceptance|Should -BeTrue
    }
  }

  It 'keeps approved Sysinternals package <Id> install planning available while acceptance remains pending' -ForEach @(
    @{ Id='package.sysinternals-suite' },
    @{ Id='package.sysinternals-process-explorer' },
    @{ Id='package.sysinternals-autoruns' },
    @{ Id='package.sysinternals-tcpview' },
    @{ Id='package.sysinternals-procmon' },
    @{ Id='package.sysinternals-rammap' },
    @{ Id='package.sysinternals-disk2vhd' },
    @{ Id='package.sysinternals-sigcheck' },
    @{ Id='package.sysinternals-strings' },
    @{ Id='package.sysinternals-handle' }
  ) {
    $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Install)
    $plan.Count | Should -Be 1
    $plan[0].Operation.Kind | Should -Be 'Package'
    $plan[0].State | Should -Be 'Present'
    $plan[0].Operation.PendingAcceptance | Should -BeTrue
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
    $export = Join-Path $script:reviewTestRoot 'roundtrip.json'
    & $script:ReviewTool Export -StorePath $script:store -Path $export | Out-Null
    $otherStore = Join-Path $script:reviewTestRoot 'other-reviews.json'
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
    $export = Join-Path $script:reviewTestRoot 'conflict.json'
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
