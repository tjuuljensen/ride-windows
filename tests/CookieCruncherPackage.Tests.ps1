<#
.SYNOPSIS
  Verify the pinned Cookie Cruncher package declaration and inert file lifecycle.
.DESCRIPTION
  Uses synthetic ZIP members to test ownership and recovery. Never launches Cookie
  Cruncher, opens browser profiles, or reads cookie data.
.EXAMPLE
  Invoke-Pester .\tests\CookieCruncherPackage.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x, Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture; Windows target and runtime acceptance remain pending.
#>
BeforeAll {
  $root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE-PortablePackages.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  $script:CookieCruncherOperation = (Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')).Operations |
    Where-Object Id -eq 'package.google-analytic-cookie-cruncher'
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
}

Describe 'Google Analytic Cookie Cruncher pending portable package' {
  BeforeEach {
    $script:CaseRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $CaseRoot
    $script:Operation = $CookieCruncherOperation.Clone()
    $Operation.SelectedVariant = 'portable'
    $Operation.ResolvedToolsDirectory = $CaseRoot
    $Operation.InstallDirectory = Join-Path $CaseRoot $Operation.PackageId
    $script:ArtifactPath = Join-Path $CaseRoot 'cookie-cruncher.zip'
    $zip = [IO.Compression.ZipFile]::Open($ArtifactPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach ($member in $Operation.RequiredFiles) {
        $entry = $zip.CreateEntry($member)
        $stream = $entry.Open()
        try {
          $bytes = [Text.Encoding]::UTF8.GetBytes("inert fixture: $member")
          $stream.Write($bytes, 0, $bytes.Length)
        }
        finally { $stream.Dispose() }
      }
    }
    finally { $zip.Dispose() }
    $script:Artifact = [pscustomobject]@{
      Path = $ArtifactPath
      Version = $Operation.PackageVersion
      Sha256 = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  }

  It 'pins the exact publisher artifact, architecture, notice and pending target' {
    $Operation.DownloadUri | Should -Match '/b384f8610475b7a04a3b4f48e98c8a82d3b771a6/Google-Analytic-Cookie-Cruncher_v_2_0_0_0_1\.zip$'
    $Operation.PackageVersion | Should -BeExactly '2.0.0.1'
    $Operation.ExpectedSha256 | Should -BeExactly '5a27c94887b25cb159f8f3477cb3cf73658dbcd1f77acba5643a88a1127b3922'
    $Operation.Architecture | Should -BeExactly 'x86'
    $Operation.Description | Should -Match '\.NET Framework 4\.0'
    $Operation.RequiredFiles | Should -Contain 'License.txt'
    $Operation.License | Should -Match 'permits redistribution'
    $Operation.PendingAcceptance | Should -BeTrue
    $Operation.SupportedTargets.Count | Should -Be 0
    $Operation.CandidateTargets | Should -Contain 'Windows 11'
    foreach ($profile in Get-ChildItem -LiteralPath (Join-Path $root 'profiles') -Filter '*.psd1') {
      [IO.File]::ReadAllText($profile.FullName) | Should -Not -Match 'package\.google-analytic-cookie-cruncher'
    }
  }

  It 'stages and repeats the owned files, then removes and restores only those files' {
    Install-RidePortablePayload $Operation $Artifact
    $output = Join-Path $Operation.InstallDirectory 'analyst-output.txt'
    [IO.File]::WriteAllText($output, 'operator output')
    Install-RidePortablePayload $Operation $Artifact
    $snapshot = Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    Uninstall-RidePortablePayload $Operation
    (Get-RidePortableState $Operation).Present | Should -BeFalse
    [IO.File]::ReadAllText($output) | Should -BeExactly 'operator output'
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy | Should -BeTrue
    [IO.File]::ReadAllText($output) | Should -BeExactly 'operator output'
  }

  It 'refuses an existing executable and preserves operator-modified bytes' {
    $null = New-Item -ItemType Directory -Path $Operation.InstallDirectory
    $exe = Join-Path $Operation.InstallDirectory 'GA Cookie Cruncher.exe'
    [IO.File]::WriteAllText($exe, 'operator file')
    { Install-RidePortablePayload $Operation $Artifact } | Should -Throw '*collision*'
    [IO.File]::ReadAllText($exe) | Should -BeExactly 'operator file'
    Remove-Item -LiteralPath $exe
    Install-RidePortablePayload $Operation $Artifact
    [IO.File]::WriteAllText($exe, 'modified after staging')
    { Install-RidePortablePayload $Operation $Artifact } | Should -Throw '*modified*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($exe) | Should -BeExactly 'modified after staging'
  }

  It 'stages and restores the retained real archive without launching Cookie Cruncher' {
    if ([string]::IsNullOrWhiteSpace($env:RIDE_COOKIE_CRUNCHER_FIXTURE_ARCHIVE)) {
      Set-ItResult -Skipped -Because 'No explicit retained Cookie Cruncher archive fixture was supplied.'
      return
    }
    $archivePath = [IO.Path]::GetFullPath($env:RIDE_COOKIE_CRUNCHER_FIXTURE_ARCHIVE)
    $archive = Get-Item -LiteralPath $archivePath -Force -ErrorAction Stop
    if ($archive.PSIsContainer -or ($archive.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'Retained Cookie Cruncher archive fixture must be a regular file.'
    }
    $sha = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sha | Should -BeExactly $CookieCruncherOperation.ExpectedSha256.ToLowerInvariant()

    $fixtureBase = Join-Path $root '.local/cookie-cruncher-current-source-real-archive'
    $runRoot = Join-Path $fixtureBase ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $runRoot -Force
    try {
      $operation = $CookieCruncherOperation.Clone()
      $operation.SelectedVariant = 'portable'
      $operation.ResolvedToolsDirectory = $runRoot
      $operation.InstallDirectory = Join-Path $runRoot $operation.PackageId
      $artifact = [pscustomobject]@{ Path = $archivePath; Sha256 = $sha; Version = $operation.PackageVersion }

      Install-RidePortablePayload $operation $artifact -Offline
      Install-RidePortablePayload $operation $artifact -Offline
      $state = Get-RidePortableState $operation
      $state.Healthy | Should -BeTrue
      $state.Files.Count | Should -Be 3
      @($state.Files.RelativePath | Sort-Object) | Should -Be @('GA Cookie Cruncher.exe', 'License.txt', 'System.Data.SQLite.dll')

      $snapshot = Save-RidePortableSnapshot $operation (Join-Path $runRoot 'backup')
      $output = Join-Path $operation.InstallDirectory 'operator-output.txt'
      [IO.File]::WriteAllText($output, 'preserve')
      Uninstall-RidePortablePayload $operation
      (Get-RidePortableState $operation).Present | Should -BeFalse
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
      [IO.File]::ReadAllText($output) | Should -BeExactly 'preserve'
    }
    finally {
      $resolved = [IO.Path]::GetFullPath($runRoot).TrimEnd('\', '/')
      $base = [IO.Path]::GetFullPath($fixtureBase).TrimEnd('\', '/')
      if ([IO.Path]::GetDirectoryName($resolved) -ine $base -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$') {
        throw 'Refusing Cookie Cruncher archive fixture cleanup outside its unique workspace-local directory.'
      }
      if (Test-Path -LiteralPath $resolved -PathType Container) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
  }
}
