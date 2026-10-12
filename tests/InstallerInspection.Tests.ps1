<#
.SYNOPSIS
  Verify sample inspection and ZIP installer handling without execution or network.
.DESCRIPTION
  Creates inert PE headers and ZIP fixtures; mocks download and installer calls.
.EXAMPLE
  Invoke-Pester .\tests\InstallerInspection.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
#>

BeforeAll {
  $script:Root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Root 'modules/RIDE.InstallerInspection.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.LibraryAuthoring.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE-Packages.psm1') -Force
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
  function New-InertInstallerZip {
    param([string] $Path, [string[]] $Names = @('setup.exe'), [switch] $Html, [switch] $Msi)
    $bytes = New-Object byte[] 128
    $bytes[0] = 0x4d; $bytes[1] = 0x5a; $bytes[60] = 64
    $bytes[64] = 0x50; $bytes[65] = 0x45; $bytes[68] = 0x4c; $bytes[69] = 1
    if ($Msi) { ([byte[]]@(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)).CopyTo($bytes, 0) }
    if ($Html) { $bytes = [Text.Encoding]::UTF8.GetBytes('<html>not an installer</html>') }
    $nativePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $archive = [IO.Compression.ZipFile]::Open($nativePath, [IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach ($name in $Names) {
        $entry = $archive.CreateEntry($name); $stream = $entry.Open()
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
      }
      $entry = $archive.CreateEntry('license.txt'); $stream = $entry.Open()
      try { $stream.WriteByte(65) } finally { $stream.Dispose() }
    } finally { $archive.Dispose() }
    $nativePath
  }
  function New-ZipPackage {
    @{
      Id = 'test.zip.games'; Kind = 'Package'; Name = 'Inert package'; Description = 'Not executable.'
      Scope = 'Machine'; SupportedTargets = @('Windows 11'); PackageId = 'test.zip.games'
      InstallerType = 'Exe'; ArchiveType = 'Zip'; InstallerEntry = 'setup.exe'; Architecture = 'x64'
      DownloadProvider = 'DirectHttps'; DownloadUri = 'https://publisher.example.invalid/games.zip'
      PackageVersion = '1.0'; AssetName = 'games.zip'; DisplayNamePattern = '^Games$'
      InstallerArguments = '/S'; UninstallerArguments = '/S'; License = 'Unknown'; LicenseUri = 'https://publisher.example.invalid/license'
    }
  }
}

Describe 'Installer sample inspection' {
  BeforeEach { $script:Zip = New-InertInstallerZip (Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.zip')) }
  It 'identifies content, the single member, launcher architecture and separate hashes' {
    $sample = Get-RideInstallerInspection -Path $script:Zip -Confirm:$false
    $sample.ArchiveType | Should -Be 'Zip'
    $sample.InstallerType | Should -Be 'Exe'
    $sample.BinaryArchitecture | Should -Be 'x86'
    $sample.InstallerEntry | Should -Be 'setup.exe'
    $sample.Sha256 | Should -Not -Be $sample.InstallerSha256
    $sample.Candidates.Count | Should -Be 1
  }
  It 'requires selection when a ZIP contains multiple installers' {
    $zip = New-InertInstallerZip (Join-Path $TestDrive 'multi.zip') @('x86/setup.exe', 'x64/setup.exe')
    $sample = Get-RideInstallerInspection -Path $zip -Confirm:$false
    $sample.Candidates.Count | Should -Be 2
    $sample.InstallerType | Should -BeNullOrEmpty
    (Get-RideInstallerInspection -Path $zip -InstallerEntry 'x64/setup.exe' -Confirm:$false).InstallerType | Should -Be 'Exe'
  }
  It 'rejects HTML renamed as an installer' {
    $zip = New-InertInstallerZip (Join-Path $TestDrive 'html.zip') -Html
    { Get-RideInstallerInspection -Path $zip -Confirm:$false } | Should -Throw '*content is not*'
  }
  It 'rejects unsafe paths and duplicate case-insensitive members without expanding other entries' {
    $destination = Join-Path $TestDrive 'selected.exe'
    { Expand-RideInstallerEntry -Path $script:Zip -Entry '../setup.exe' -Destination $destination } | Should -Throw '*Unsafe*'
    $zip = New-InertInstallerZip (Join-Path $TestDrive 'duplicates.zip') @('setup.exe', 'SETUP.exe')
    { Expand-RideInstallerEntry -Path $zip -Entry 'setup.exe' -Destination $destination } | Should -Throw '*exactly one*'
    Expand-RideInstallerEntry -Path $script:Zip -Entry 'setup.exe' -Destination $destination
    Test-Path -LiteralPath (Join-Path $TestDrive 'license.txt') | Should -BeFalse
    { Expand-RideInstallerEntry -Path $script:Zip -Entry 'setup.exe' -Destination $destination } | Should -Throw
  }
  It 'rejects oversized archives by entry count before extraction' {
    $zip = New-InertInstallerZip (Join-Path $TestDrive 'many.zip') @(1..129 | ForEach-Object { "$_.exe" })
    { Get-RideInstallerInspection -Path $zip -Confirm:$false } | Should -Throw '*entry-count*'
  }
  It 'downloads only on request and WhatIf makes no network request' {
    Mock Invoke-RideInspectionDownload -ModuleName RIDE.InstallerInspection { Copy-Item -LiteralPath $script:Zip -Destination $Destination }
    $sample = Get-RideInstallerInspection -Uri 'https://publisher.example.invalid/setup.zip' -Confirm:$false
    $sample.InstallerType | Should -Be 'Exe'
    Get-RideInstallerInspection -Uri 'https://publisher.example.invalid/setup.zip' -WhatIf | Should -BeNullOrEmpty
    Should -Invoke Invoke-RideInspectionDownload -ModuleName RIDE.InstallerInspection -Times 1 -Exactly
  }
  It 'validates HTTPS before creating a download' {
    { Get-RideInstallerInspection -Uri 'http://publisher.example.invalid/setup.zip' -Confirm:$false } | Should -Throw '*HTTPS*'
  }
  It 'completes ZIP member paths from the selected local file without downloads' {
    foreach ($command in @('Get-RideInstallerInspection', 'Expand-RideInstallerEntry')) {
      $parameter = if ($command -eq 'Get-RideInstallerInspection') { 'InstallerEntry' } else { 'Entry' }
      $text = "$command -Path '$script:Zip' -$parameter set"
      $completion = TabExpansion2 -inputScript $text -cursorColumn $text.Length
      $completion.CompletionMatches.ListItemText | Should -Contain 'setup.exe'
    }
  }
  It 'asks for the sample before package metadata and offers reviewed resource defaults' {
    $global:RideZipPromptState = @{ Index = 0; SamplePath = $script:Zip; Responses = @(
      'test.zip', '', '1', '2', 'https://publisher.example.invalid/sample.zip',
      'games', '', 'Fixture package', '2', '1', '', '', '', '', '1', '', '', '', '', '',
      'Actual installed name', '/S', '/S', 'Unknown', 'https://publisher.example.invalid/license', '', '', '1', '', '1'
    ) }
    Mock Read-Host {
      $state = $global:RideZipPromptState
      if ($state.Index -ge $state.Responses.Count) { throw 'Unexpected ZIP authoring prompt.' }
      $answer = $state.Responses[$state.Index]; $state.Index++; $answer
    }
    Mock Invoke-RideInspectionDownload -ModuleName RIDE.InstallerInspection {
      $global:RideZipPromptState.Index | Should -Be 5
      Copy-Item -LiteralPath $global:RideZipPromptState.SamplePath -Destination $Destination
    }
    Mock Get-RideInstallerFileDetails -ModuleName RIDE.InstallerInspection {
      [pscustomobject]@{ InstallerType = 'Exe'; BinaryArchitecture = 'x86'; ProductName = 'Resource name'; ProductVersion = '4.3'; Sha256 = 'a' * 64 }
    }
    try {
      $project = & (Join-Path $script:Root 'tools/New-RideLibrary.ps1') -Path (Join-Path $TestDrive 'guided-library') -Confirm:$false
      $operation = (Import-RideCatalogData -Path (Join-Path $project.Path 'catalog/operations.psd1')).Operations[0]
      $operation.Name | Should -Be 'Resource name'
      $operation.PackageVersion | Should -Be '4.3'
      $operation.Architecture | Should -Be 'x64'
      $operation.InstallerEntry | Should -Be 'setup.exe'
      $operation.AssetName | Should -Be 'sample.zip'
      $operation.DisplayNamePattern | Should -Be '^Actual\ installed\ name$'
      $operation.ContainsKey('ExpectedSha256') | Should -BeFalse
      $operation.ContainsKey('ExpectedInstallerSha256') | Should -BeFalse
      $global:RideZipPromptState.Index | Should -Be $global:RideZipPromptState.Responses.Count
      Should -Invoke Invoke-RideInspectionDownload -ModuleName RIDE.InstallerInspection -Times 1 -Exactly
    } finally { Remove-Variable RideZipPromptState -Scope Global -ErrorAction SilentlyContinue }
  }
  It 'cancels during multi-installer selection without publishing or downloading again' {
    $zip = New-InertInstallerZip (Join-Path $TestDrive 'cancel-multi.zip') @('one.exe', 'two.exe')
    $global:RideZipPromptState = @{ Index = 0; Responses = @('test.zip', '', '1', '3', $zip, ':cancel') }
    Mock Read-Host {
      $state = $global:RideZipPromptState
      if ($state.Index -ge $state.Responses.Count) { throw 'Unexpected prompt after cancellation.' }
      $answer = $state.Responses[$state.Index]; $state.Index++; $answer
    }
    $outputPath = Join-Path $TestDrive 'cancelled-library'
    try {
      { & (Join-Path $script:Root 'tools/New-RideLibrary.ps1') -Path $outputPath -Confirm:$false } | Should -Throw '*Authoring cancelled*'
      Test-Path -LiteralPath $outputPath | Should -BeFalse
    } finally { Remove-Variable RideZipPromptState -Scope Global -ErrorAction SilentlyContinue }
  }
}

Describe 'ZIP custom-library lifecycle metadata' {
  BeforeEach {
    $script:Zip = New-InertInstallerZip (Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.zip'))
    $script:Package = New-ZipPackage
    $script:Package.ExpectedInstallerSha256 = (Get-RideInstallerInspection -Path $script:Zip -Confirm:$false).InstallerSha256
  }
  It 'publishes ZIP metadata and keeps archive and installer hashes distinct' {
    $operation = $script:Package.Clone(); $operation.Id = 'games'; $operation.Remove('PackageId')
    $definition = @{ Id = 'test.zip'; Version = '0.1.0'; Operations = @($operation) }
    $project = New-RideLibraryProject -Path (Join-Path $TestDrive 'library') -Definition $definition -Confirm:$false
    Test-Path -LiteralPath $project.Manifest | Should -BeTrue
    (Resolve-RidePackageArtifact -Operation $script:Package).FileName | Should -Be 'games.zip'
    $operation.InstallerEntry = '../setup.exe'
    { New-RideLibraryProject -Path (Join-Path $TestDrive 'bad-library') -Definition $definition -Confirm:$false } | Should -Throw '*safe matching*'
  }
  It 'retains the archive and records a verified selected-member hash' {
    Mock Invoke-WebRequest -ModuleName RIDE-Packages { Copy-Item -LiteralPath $script:Zip -Destination $OutFile }
    Mock Add-RideArtifactObservation -ModuleName RIDE-Packages {}
    $saved = Save-RidePackageArtifact -Operation $script:Package -DestinationDirectory (Join-Path $TestDrive 'cache')
    Test-Path -LiteralPath $saved.Path | Should -BeTrue
    Should -Invoke Add-RideArtifactObservation -ModuleName RIDE-Packages -Times 1 -ParameterFilter { $Contents.Count -eq 1 -and $Contents[0].ArchivePath -eq 'setup.exe' -and $Contents[0].Sha256 -eq $script:Package.ExpectedInstallerSha256 }
  }
  It 'runs only the selected installer through a mocked process and cleans staging' {
    Mock Save-RidePackageArtifact -ModuleName RIDE-Packages { [pscustomobject]@{ Path = $script:Zip } }
    Mock Get-RideInstalledPackage -ModuleName RIDE-Packages { [pscustomobject]@{ Present = $true } }
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages {
      Test-Path -LiteralPath $FilePath | Should -BeTrue
      [IO.File]::ReadAllBytes($FilePath).Length | Should -Be 128
      $global:RideZipTestInstallerPath = $FilePath
      [pscustomobject]@{ ExitCode = 0 }
    }
    try {
      Install-RidePackage -Operation $script:Package -CacheDirectory $TestDrive
      Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Times 1 -Exactly
      Test-Path -LiteralPath $global:RideZipTestInstallerPath | Should -BeFalse
      Test-Path -LiteralPath $script:Zip | Should -BeTrue
    } finally { Remove-Variable RideZipTestInstallerPath -Scope Global -ErrorAction SilentlyContinue }
  }
  It 'stops before execution on a mismatched inner hash and retains the archive' {
    Mock Save-RidePackageArtifact -ModuleName RIDE-Packages { [pscustomobject]@{ Path = $script:Zip } }
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages { throw 'Must not execute.' }
    $script:Package.ExpectedInstallerSha256 = '0' * 64
    { Install-RidePackage -Operation $script:Package -CacheDirectory $TestDrive } | Should -Throw '*digest mismatch*'
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Times 0 -Exactly
    Test-Path -LiteralPath $script:Zip | Should -BeTrue
  }
  It 'dispatches a ZIP-contained MSI through mocked msiexec with the extracted path' {
    $script:Zip = New-InertInstallerZip (Join-Path $TestDrive 'msi.zip') @('setup.msi') -Msi
    $script:Package.InstallerType = 'Msi'; $script:Package.InstallerEntry = 'setup.msi'
    $script:Package.InstallerArguments = '/qn /norestart'; $script:Package.Remove('ExpectedInstallerSha256')
    Mock Save-RidePackageArtifact -ModuleName RIDE-Packages { [pscustomobject]@{ Path = $script:Zip } }
    Mock Get-RideInstalledPackage -ModuleName RIDE-Packages { [pscustomobject]@{ Present = $true } }
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages {
      $FilePath | Should -BeLike '*\System32\msiexec.exe'
      $ArgumentList | Should -Match '^/i "[^"\r\n]+setup\.msi" /qn /norestart$'
      [pscustomobject]@{ ExitCode = 0 }
    }
    Install-RidePackage -Operation $script:Package -CacheDirectory $TestDrive
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Times 1 -Exactly
  }
}
