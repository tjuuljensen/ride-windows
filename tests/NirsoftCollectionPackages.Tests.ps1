<#
.SYNOPSIS
  Validate pinned NirSoft collection candidates and Defender-reported exclusions.
.DESCRIPTION
  Uses frozen JSON inventories and catalog metadata only. It never opens or
  extracts an alert-reported executable and never runs NirSoft utilities.
.EXAMPLE
  Invoke-Pester .\tests\NirsoftCollectionPackages.Tests.ps1
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture; candidates remain pending Windows acceptance.
#>
BeforeAll {
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog = Get-RideCatalog
  $script:LauncherBlockedExecutableNames = @('chromecookiesview.exe', 'bulletspassview.exe', 'produkey.exe', 'wirelesskeyview.exe', 'iehv.exe', 'lanipscanner.exe', 'lsasecretsdump.exe', 'operapassview.exe', 'routerpassview.exe', 'netpass.exe', 'webbrowserbookmarksview.exe', 'browserautofillview.exe', 'passwordscan.exe')
  $script:X64BlockedExecutableNames = @('produkey.exe', 'wirelesskeyview.exe')
  $script:LauncherEvidence = Get-Content -LiteralPath (Join-Path $script:RepositoryRoot 'docs/archive/evidence/nirlauncher-source-inventory-2026-10-17.json') -Raw | ConvertFrom-Json
  $script:X64Evidence = Get-Content -LiteralPath (Join-Path $script:RepositoryRoot 'docs/archive/evidence/nirsoft-x64-source-review-2026-10-17.json') -Raw | ConvertFrom-Json
}

Describe 'NirSoft collection portable candidates' {
  It 'pins the NirLauncher publisher snapshot and omits all alerted or Defender-blocked tools' {
    $operation = @($script:Catalog.Operations | Where-Object Id -ceq 'package.nirsoft-launcher')[0]
    $expected = @($script:LauncherEvidence.Members | Where-Object { [IO.Path]::GetFileName([string]$_.Path) -notin $script:LauncherBlockedExecutableNames } | ForEach-Object { [string]$_.Path })
    $operation.PackageVersion | Should -BeExactly $script:LauncherEvidence.PublisherVersion
    $operation.ExpectedSha256 | Should -BeExactly $script:LauncherEvidence.Sha256
    $operation.PortableMembers.Count | Should -Be 647
    $operation.PortableArchivePassword | Should -Match '^[A-Za-z0-9!$._-]{1,64}$'
    $operation.AcceptanceNotes | Should -Match 'Defender prevented their staging'
    @($operation.PortableMembers | Where-Object { [IO.Path]::GetFileName([string]$_) -in $script:LauncherBlockedExecutableNames }).Count | Should -Be 0
    @(Compare-Object $operation.PortableMembers $expected -CaseSensitive).Count | Should -Be 0
    @($operation.RequiredFiles | Where-Object { $_ -notin $operation.PortableMembers }).Count | Should -Be 0
    $operation.SupportedTargets | Should -BeNullOrEmpty
    $operation.PendingAcceptance | Should -BeTrue
    $operation.AcceptanceNotes | Should -Match 'individual NirLauncher member hashes were not verified'
  }

  It 'pins the measured x64 package and omits both reported alert executables' {
    $operation = @($script:Catalog.Operations | Where-Object Id -ceq 'package.nirsoft-x64-tools')[0]
    $expected = @($script:X64Evidence.Members | Where-Object { [IO.Path]::GetFileName([string]$_.Path) -notin $script:X64BlockedExecutableNames } | ForEach-Object { [string]$_.Path })
    $operation.ExpectedSha256 | Should -BeExactly $script:X64Evidence.Sha256
    $operation.PortableMembers.Count | Should -Be 47
    @($operation.PortableMembers | Where-Object { [IO.Path]::GetFileName([string]$_) -in $script:X64BlockedExecutableNames }).Count | Should -Be 0
    @(Compare-Object $operation.PortableMembers $expected -CaseSensitive).Count | Should -Be 0
    $operation.SupportedTargets | Should -BeNullOrEmpty
    $operation.PendingAcceptance | Should -BeTrue
    $operation.AcceptanceNotes | Should -Match 'publisher supplied no archive digest'
  }

  It 'keeps the NK2Edit business-use exception visible without blocking package planning' {
    $operation = @($script:Catalog.Operations | Where-Object Id -ceq 'package.nirsoft-launcher')[0]
    $operation.License | Should -Match 'NK2Edit requires a separate commercial license'
    $operation.LicenseUri | Should -BeExactly 'https://launcher.nirsoft.net/'
    $operation.CandidateTargets | Should -Contain 'Windows 11'
  }

  It 'stages, repeats, removes and restores a safe representative for both filtered candidates' {
    foreach ($id in @('package.nirsoft-launcher', 'package.nirsoft-x64-tools')) {
      $operation = @($script:Catalog.Operations | Where-Object Id -ceq $id)[0].Clone()
      $operation.Remove('PortableArchivePassword')
      $blockedNames = if ($id -ceq 'package.nirsoft-launcher') { $script:LauncherBlockedExecutableNames } else { $script:X64BlockedExecutableNames }
      @($operation.PortableMembers | Where-Object { [IO.Path]::GetFileName([string]$_) -in $blockedNames }).Count | Should -Be 0
      $sampleMembers = @($operation.RequiredFiles) + @($operation.PortableMembers | Where-Object { $_ -notin $operation.RequiredFiles } | Select-Object -First 1)
      $operation.PortableMembers = @($sampleMembers | Select-Object -Unique)
      $caseRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $null = New-Item -ItemType Directory -Path $caseRoot -Force
      $operation.ResolvedToolsDirectory = Join-Path $caseRoot 'tools'
      $operation.InstallDirectory = Join-Path $operation.ResolvedToolsDirectory $operation.PackageId
      $archivePath = Join-Path $caseRoot 'synthetic-inert.zip'
      $unselectedMember = 'NirSoft/x64/unselected-test-fixture.txt'
      $archive = [IO.Compression.ZipFile]::Open($archivePath, [IO.Compression.ZipArchiveMode]::Create)
      try {
        foreach ($member in $operation.PortableMembers) {
          $entry = $archive.CreateEntry([string]$member)
          $writer = [IO.StreamWriter]::new($entry.Open())
          try { $writer.Write('inert test fixture') } finally { $writer.Dispose() }
        }
        $entry = $archive.CreateEntry($unselectedMember)
        $writer = [IO.StreamWriter]::new($entry.Open())
        try { $writer.Write('inert unselected fixture') } finally { $writer.Dispose() }
      } finally { $archive.Dispose() }

      $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
      $operation.ExpectedSha256 = $hash
      $artifact = [pscustomobject]@{ Path = $archivePath; Sha256 = $hash; Version = $operation.PackageVersion }
      Install-RidePortablePayload $operation $artifact -Offline
      Install-RidePortablePayload $operation $artifact -Offline
      $state = Get-RidePortableState $operation
      $state.Healthy | Should -BeTrue
      $state.Files.Count | Should -Be $operation.PortableMembers.Count
      @($state.Files | Where-Object { $_.RelativePath -notin $operation.PortableMembers }).Count | Should -Be 0
      @($state.Files | Where-Object { [IO.Path]::GetFileName($_.RelativePath) -in $blockedNames }).Count | Should -Be 0
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory $unselectedMember) | Should -BeFalse

      $snapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'snapshot')
      $customPath = Join-Path $operation.InstallDirectory 'operator-note.txt'
      [IO.File]::WriteAllText($customPath, 'preserve operator content')
      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $snapshot
      $restored = Get-RidePortableState $operation
      $restored.Healthy | Should -BeTrue
      $restored.Files.Count | Should -Be $operation.PortableMembers.Count
      [IO.File]::ReadAllText($customPath) | Should -BeExactly 'preserve operator content'
    }
  }

  It 'reviews retained encrypted publisher ZIP inventory without extracting payloads' {
    $fixtureDirectory = [Environment]::GetEnvironmentVariable('RIDE_NIRSOFT_FIXTURE_DIRECTORY')
    if ([string]::IsNullOrWhiteSpace($fixtureDirectory) -or -not (Test-Path -LiteralPath $fixtureDirectory -PathType Container)) {
      Set-ItResult -Skipped -Because 'Set RIDE_NIRSOFT_FIXTURE_DIRECTORY to the retained publisher archive directory to enable this check.'
      return
    }

    $cases = @(
      [pscustomobject]@{
        Id = 'package.nirsoft-launcher'
        ArchiveName = 'nirlauncher-referred.zip'
        Evidence = $script:LauncherEvidence
        BlockedExecutableNames = $script:LauncherBlockedExecutableNames
        Bytes = 41961437
        Sha256 = '6cfd973d0f2d34ec2fe5c7cfdcc0bdbcb56a8fad329fb4683f6446602769f1b2'
        ObservedMembers = 668
        BlockedEntries = 21
      },
      [pscustomobject]@{
        Id = 'package.nirsoft-x64-tools'
        ArchiveName = 'x64tools.zip'
        Evidence = $script:X64Evidence
        BlockedExecutableNames = $script:X64BlockedExecutableNames
        Bytes = 2105172
        Sha256 = '305556bfa9796fd5320ffe4f87ccc66a1fca6dad5fed7d5653bc21ac5df2806b'
        ObservedMembers = 49
        BlockedEntries = 2
      }
    )
    $archiveFilter = [Environment]::GetEnvironmentVariable('RIDE_NIRSOFT_ARCHIVE_FILTER')

    foreach ($case in @($cases | Where-Object { -not $archiveFilter -or $_.ArchiveName -ieq $archiveFilter })) {
      $archivePath = Join-Path $fixtureDirectory $case.ArchiveName
      $archivePath | Should -Exist
      (Get-Item -LiteralPath $archivePath).Length | Should -Be $case.Bytes
      $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
      $archiveHash | Should -BeExactly $case.Sha256

      $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
      try {
        $archive.Entries.Count | Should -Be $case.ObservedMembers
        $observedMembers = @($archive.Entries | Where-Object { -not $_.FullName.EndsWith('/') } | ForEach-Object FullName)
        $expectedMembers = @($case.Evidence.Members | ForEach-Object { [string]$_.Path })
        @(Compare-Object $observedMembers $expectedMembers -CaseSensitive).Count | Should -Be 0
        @($archive.Entries | Where-Object { [IO.Path]::GetFileName($_.FullName) -in $case.BlockedExecutableNames }).Count | Should -Be $case.BlockedEntries
      } finally { $archive.Dispose() }

      $operation = @($script:Catalog.Operations | Where-Object Id -ceq $case.Id)[0].Clone()
      @($operation.PortableMembers | Where-Object { [IO.Path]::GetFileName([string]$_) -in $case.BlockedExecutableNames }).Count | Should -Be 0
      $operation.PortableArchivePassword | Should -Match '^[A-Za-z0-9!$._-]{1,64}$'
      $missingSelectedMembers = @($operation.PortableMembers | Where-Object { $_ -notin $observedMembers })
      $missingSelectedMembers.Count | Should -Be 0
    }
  }

}
