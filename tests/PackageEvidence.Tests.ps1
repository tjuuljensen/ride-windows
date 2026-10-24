<#
.SYNOPSIS
  Verify acquisition evidence, publisher checksums and rejected-artifact cache handling.
.DESCRIPTION
  Uses mocked HTTP/signature calls and TestDrive fixtures. No Windows changes.
.EXAMPLE
  Invoke-Pester .\tests\PackageEvidence.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.7.1.
  Owner: RIDE-Windows maintainers. Repository test fixture; no standalone CLI.
#>


BeforeDiscovery {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE-Packages.psm1') -Force
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.CatalogData.psm1') -Force
}

Describe 'Publisher evidence and acquisition provenance' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $script:GitHubReleaseCache = @{}; $script:GitHubReleaseNotBefore = $null; $script:GitHubReleaseRate = $null
      $localRoot = Join-Path (Split-Path -Parent $PSScriptRoot) '.local'
      if (-not (Test-Path -LiteralPath $localRoot -PathType Container)) { $null = New-Item -ItemType Directory -Path $localRoot }
      if ((Get-Item -LiteralPath $localRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package evidence fixtures cannot use a reparse-point .local directory.' }
      $script:PackageEvidenceTestRoot = Join-Path $localRoot ('package-evidence-tests-' + [guid]::NewGuid().ToString('N'))
      $null = New-Item -ItemType Directory -Path $script:PackageEvidenceTestRoot
    }
    AfterEach {
      if ([IO.Directory]::Exists($script:PackageEvidenceTestRoot)) {
        $resolvedRoot = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $script:PackageEvidenceTestRoot).Path)
        $expectedParent = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) '.local'))
        if (([IO.Path]::GetDirectoryName($resolvedRoot) -cne $expectedParent) -or
            (Split-Path -Leaf $resolvedRoot) -notmatch '^package-evidence-tests-[0-9a-f]{32}$' -or
            (([IO.File]::GetAttributes($resolvedRoot) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Refusing to clean an unexpected package evidence fixture path.' }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
      }
    }
    It 'checks a provider SHA-512 before recording acquisition and rejects altered bytes' {
      $script:sha512Fixture=Join-Path $script:PackageEvidenceTestRoot 'publisher-bytes.exe'
      [IO.File]::WriteAllText($script:sha512Fixture,'publisher checked bytes')
      $script:providerSha512=(Get-FileHash -LiteralPath $script:sha512Fixture -Algorithm SHA512).Hash.ToLowerInvariant()
      $cache=Join-Path $script:PackageEvidenceTestRoot 'sha512'
      Mock Resolve-RidePackageArtifact { [pscustomobject]@{PackageId='sha512-fixture';Version='1';FileName='app.exe';Uri='https://example.org/app.exe';ProviderDigest=('sha512:'+$script:providerSha512)} }
      Mock Invoke-WebRequest { Copy-Item -LiteralPath $script:sha512Fixture -Destination $OutFile }
      Mock Get-AuthenticodeSignature { [pscustomobject]@{Status='NotSigned';SignerCertificate=$null;TimeStamperCertificate=$null} }
      Mock Add-RideArtifactObservation {}
      $saved=Save-RidePackageArtifact @{Kind='Package';PackageId='sha512-fixture'} $cache
      $saved.ProviderDigest | Should -Be ('sha512:'+$script:providerSha512)
      [IO.File]::WriteAllText($saved.Path+'.ride.json','{"Kind":"PreviousObservation"}')
      [IO.File]::AppendAllText($saved.Path,'altered')
      { Save-RidePackageArtifact @{Kind='Package';PackageId='sha512-fixture'} $cache } | Should -Throw '*Provider SHA-512 digest mismatch*'
      Test-Path -LiteralPath $saved.Path | Should -BeFalse
      $rejected = @(Get-ChildItem -LiteralPath (Split-Path -Parent $saved.Path) -Filter 'app.exe.rejected-*' -File | Where-Object Name -Match '^app\.exe\.rejected-[0-9a-f]{32}$')
      $rejected.Count | Should -Be 1
      Test-Path -LiteralPath ($saved.Path + '.ride.json') | Should -BeFalse
      Test-Path -LiteralPath ($rejected[0].FullName + '.ride.json') | Should -BeTrue
      Test-Path -LiteralPath ($rejected[0].FullName + '.previous.ride.json') | Should -BeTrue
      (Get-Content -LiteralPath ($rejected[0].FullName + '.previous.ride.json') -Raw | ConvertFrom-Json).Kind | Should -BeExactly PreviousObservation
      Should -Invoke Add-RideArtifactObservation -Exactly 1
    }
    It 'rejects release assets from a mirror or a different GitHub project' {
      Mock Invoke-WebRequest {
        $release = [pscustomobject]@{ tag_name = '1.0'; assets = @([pscustomobject]@{ name = 'app.exe'; browser_download_url = $script:untrustedAssetUri }) }
        [pscustomobject]@{ Content = ($release | ConvertTo-Json -Depth 8); Headers = @{} }
      } -ParameterFilter { $Uri -like 'https://api.github.com/repos/*/releases/latest' -and -not $OutFile }
      foreach ($uri in @('https://mirror.example.org/app.exe', 'https://github.com/other/project/releases/download/1.0/app.exe', 'https://github.com/publisher/project-other/releases/download/1.0/app.exe')) {
        $script:GitHubReleaseCache = @{}
        $script:untrustedAssetUri = $uri
        { Resolve-RidePackageArtifact @{ PackageId = 'app'; DownloadProvider = 'GitHubReleaseApi'; DownloadUri = 'https://api.github.com/repos/publisher/project/releases/latest'; AssetPattern = '^app.exe$'; Architecture = 'x64' } } | Should -Throw '*declared publisher repository*'
      }
    }

    It 'reads the exact installer checksum from publisher release notes' {
      Mock Invoke-WebRequest {
        $release = [pscustomobject]@{ tag_name = 'v2.56.0.windows.2'; html_url = 'https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.2'; body = '| Git-2.56.0.2-64-bit.exe | ' + ('a' * 64) + ' |'; assets = @([pscustomobject]@{ name = 'Git-2.56.0.2-64-bit.exe'; browser_download_url = 'https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/Git-2.56.0.2-64-bit.exe'; digest = $null }) }
        [pscustomobject]@{ Content = ($release | ConvertTo-Json -Depth 8); Headers = @{} }
      } -ParameterFilter { $Uri -like 'https://api.github.com/repos/*/releases/latest' -and -not $OutFile }
      $operation = @{ PackageId = 'git-for-windows'; DownloadProvider = 'GitHubReleaseApi'; DownloadUri = 'https://api.github.com/repos/git-for-windows/git/releases/latest'; AssetPattern = '^Git-\d+(?:\.\d+){2,3}-64-bit\.exe$'; Architecture = 'x64'; PublisherChecksumSource = 'ReleaseNotes' }
      $resolved = Resolve-RidePackageArtifact $operation
      $resolved.PublisherSha256 | Should -Be ('a' * 64)
      $resolved.ProviderDigest | Should -BeNullOrEmpty
    }

    It 'rejects conflicting checksum evidence for the selected filename' {
      Mock Invoke-WebRequest {
        $release = [pscustomobject]@{ tag_name = 'v1'; html_url = 'https://github.com/example/app/releases/tag/v1'; body = ('a' * 64) + " app.exe`n" + ('b' * 64) + ' app.exe'; assets = @([pscustomobject]@{ name = 'app.exe'; browser_download_url = 'https://github.com/example/app/releases/download/v1/app.exe' }) }
        [pscustomobject]@{ Content = ($release | ConvertTo-Json -Depth 8); Headers = @{} }
      } -ParameterFilter { $Uri -like 'https://api.github.com/repos/*/releases/latest' -and -not $OutFile }
      $operation = @{ PackageId = 'app'; DownloadProvider = 'GitHubReleaseApi'; DownloadUri = 'https://api.github.com/repos/example/app/releases/latest'; AssetPattern = '^app\.exe$'; PublisherChecksumSource = 'ReleaseNotes' }
      { Resolve-RidePackageArtifact $operation } | Should -Throw '*Conflicting publisher checksums*'
    }

    It 'retains a sidecar and distinguishes a cached observation from a download' {
      $destination = Join-Path $script:PackageEvidenceTestRoot 'artifacts'
      $library = Join-Path $script:PackageEvidenceTestRoot 'observations.json'
      Mock Resolve-RidePackageArtifact { [pscustomobject]@{ PackageId = 'app'; Version = '1'; FileName = 'app.exe'; Uri = 'https://example.org/app.exe'; ProviderDigest = $null } }
      Mock Invoke-WebRequest { 'mock artifact' | Set-Content -LiteralPath $OutFile }
      Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null; TimeStamperCertificate = $null } }
      Mock Start-Process { throw 'Acquisition must not start an installer.' }
      $operation = @{ Kind = 'Package'; PackageId = 'app'; License = 'MIT'; LicenseUri = 'https://example.org/LICENSE'; TermsUri = 'https://example.org/terms' }
      $first = Save-RidePackageArtifact $operation $destination -ObservationPath $library
      $second = Save-RidePackageArtifact $operation $destination -ObservationPath $library
      $records = (Get-Content -LiteralPath $library -Raw | ConvertFrom-Json).Observations
      $records.Count | Should -Be 2
      $records[0].AcquisitionKind | Should -Be 'Download'
      $records[1].AcquisitionKind | Should -Be 'Cache'
      $records[0].ObservationId | Should -Not -Be $records[1].ObservationId
      Test-Path -LiteralPath ($second.Path + '.ride.json') | Should -BeTrue
      $records[0].License | Should -Be 'MIT'
      $records[0].LicenseUri | Should -Be 'https://example.org/LICENSE'
      $records[1].TermsUri | Should -Be 'https://example.org/terms'
      $second.LicenseUri | Should -Be $records[1].LicenseUri
      $sidecar = Get-Content -LiteralPath ($second.Path + '.ride.json') -Raw | ConvertFrom-Json
      $sidecar.LicenseUri | Should -Be $records[1].LicenseUri
      'LicenseReviewStatus' | Should -Not -BeIn $sidecar.PSObject.Properties.Name
      Should -Invoke Invoke-WebRequest -Exactly 1
      Should -Invoke Start-Process -Exactly 0
    }

    It 'stops on a publisher checksum mismatch before recording success' {
      $destination = Join-Path $script:PackageEvidenceTestRoot 'mismatch'
      Mock Resolve-RidePackageArtifact { [pscustomobject]@{ PackageId = 'app'; Version = '1'; FileName = 'app.exe'; Uri = 'https://example.org/app.exe'; ProviderDigest = $null; PublisherSha256 = 'a' * 64 } }
      Mock Invoke-WebRequest { 'different bytes' | Set-Content -LiteralPath $OutFile }
      Mock Add-RideArtifactObservation { }
      { Save-RidePackageArtifact @{ Kind = 'Package'; PackageId = 'app' } $destination -ObservationPath (Join-Path $script:PackageEvidenceTestRoot 'mismatch.json') } | Should -Throw '*Publisher SHA-256 checksum mismatch*'
      Test-Path -LiteralPath (Join-Path $destination 'app/1/app.exe') | Should -BeFalse
      $rejected = @(Get-ChildItem -LiteralPath (Join-Path $destination 'app/1') -Filter 'app.exe.rejected-*' -File | Where-Object Name -Match '^app\.exe\.rejected-[0-9a-f]{32}$')
      $rejected.Count | Should -Be 1
      (Get-Content -LiteralPath $rejected[0].FullName -Raw) | Should -Match 'different bytes'
      $rejection = Get-Content -LiteralPath ($rejected[0].FullName + '.ride.json') -Raw | ConvertFrom-Json
      $rejection.Kind | Should -BeExactly RejectedPackageArtifact
      $rejection.Reason | Should -Match 'Publisher SHA-256 checksum mismatch'
      $rejection.Sha256 | Should -Be (Get-FileHash -LiteralPath $rejected[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      Should -Invoke Add-RideArtifactObservation -Exactly 0
    }

    It 'retries acquisition after quarantining bytes that fail publisher checksum validation' {
      $destination = Join-Path $script:PackageEvidenceTestRoot 'retry-after-mismatch'
      $library = Join-Path $script:PackageEvidenceTestRoot 'retry-after-mismatch.json'
      $validBytes = 'publisher verified bytes'
      $validFixture = Join-Path $script:PackageEvidenceTestRoot 'publisher-verified-bytes.exe'
      [IO.File]::WriteAllText($validFixture, $validBytes)
      $script:expectedPublisherSha256 = (Get-FileHash -LiteralPath $validFixture -Algorithm SHA256).Hash.ToLowerInvariant()
      $script:downloadAttempts = 0
      Mock Resolve-RidePackageArtifact { [pscustomobject]@{ PackageId = 'app'; Version = '1'; FileName = 'app.exe'; Uri = 'https://example.org/app.exe'; ProviderDigest = $null; PublisherSha256 = $script:expectedPublisherSha256 } }
      Mock Invoke-WebRequest {
        $script:downloadAttempts++
        [IO.File]::WriteAllText($OutFile, $(if ($script:downloadAttempts -eq 1) { 'wrong bytes' } else { $validBytes }))
      }
      Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null; TimeStamperCertificate = $null } }
      Mock Add-RideArtifactObservation { }

      { Save-RidePackageArtifact @{ Kind = 'Package'; PackageId = 'app' } $destination -ObservationPath $library } | Should -Throw '*Publisher SHA-256 checksum mismatch*'
      $rejected = @(Get-ChildItem -LiteralPath (Join-Path $destination 'app/1') -Filter 'app.exe.rejected-*' -File | Where-Object Name -Match '^app\.exe\.rejected-[0-9a-f]{32}$')
      $rejected.Count | Should -Be 1
      $rejection = Get-Content -LiteralPath ($rejected[0].FullName + '.ride.json') -Raw | ConvertFrom-Json
      $rejection.Reason | Should -Match 'Publisher SHA-256 checksum mismatch'
      $rejection.PreviousObservationPreservedAt | Should -BeNullOrEmpty
      $saved = Save-RidePackageArtifact @{ Kind = 'Package'; PackageId = 'app' } $destination -ObservationPath $library
      [IO.File]::ReadAllText($saved.Path) | Should -BeExactly $validBytes
      Test-Path -LiteralPath $rejected[0].FullName -PathType Leaf | Should -BeTrue
      Should -Invoke Invoke-WebRequest -Exactly 2
      Should -Invoke Add-RideArtifactObservation -Exactly 1
    }

    It 'does not retain an interrupted download as a reusable artifact' {
      $destination=Join-Path $script:PackageEvidenceTestRoot 'interrupted'
      Mock Resolve-RidePackageArtifact { [pscustomobject]@{PackageId='app';Version='1';FileName='app.exe';Uri='https://example.org/app.exe'} }
      Mock Invoke-WebRequest { [IO.File]::WriteAllText($OutFile,'partial bytes'); throw 'simulated network interruption' }
      Mock Add-RideArtifactObservation {}
      { Save-RidePackageArtifact @{Kind='Package';PackageId='app'} $destination } | Should -Throw '*network interruption*'
      @(Get-ChildItem -LiteralPath $destination -Recurse -File).Count | Should -Be 0
      Should -Invoke Add-RideArtifactObservation -Exactly 0
    }

    It 'stops on changed signed bytes before recording successful acquisition' {
      $destination = Join-Path $script:PackageEvidenceTestRoot 'bad-signature'
      Mock Resolve-RidePackageArtifact { [pscustomobject]@{PackageId='app';Version='1';FileName='app.exe';Uri='https://example.org/app.exe'} }
      Mock Invoke-WebRequest { 'bytes' | Set-Content -LiteralPath $OutFile }
      Mock Get-AuthenticodeSignature { [pscustomobject]@{Status='HashMismatch';SignerCertificate=$null;TimeStamperCertificate=$null} }
      Mock Add-RideArtifactObservation {}
      { Save-RidePackageArtifact @{Kind='Package';PackageId='app'} $destination } | Should -Throw '*signature integrity failure*'
      Test-Path -LiteralPath (Join-Path $destination 'app/1/app.exe') | Should -BeFalse
      $rejected = @(Get-ChildItem -LiteralPath (Join-Path $destination 'app/1') -Filter 'app.exe.rejected-*' -File | Where-Object Name -Match '^app\.exe\.rejected-[0-9a-f]{32}$')
      $rejected.Count | Should -Be 1
      $rejection = Get-Content -LiteralPath ($rejected[0].FullName + '.ride.json') -Raw | ConvertFrom-Json
      $rejection.Reason | Should -Match 'signature integrity failure'
      Should -Invoke Add-RideArtifactObservation -Exactly 0
    }

    It 'binds Sysmon executable evidence to its parent archive before installation' {
      $fixtureRoot = Join-Path $script:PackageEvidenceTestRoot 'archive-source'
      New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
      'mock executable' | Set-Content -LiteralPath (Join-Path $fixtureRoot 'Sysmon64.exe')
      $fixtureZip = Join-Path $script:PackageEvidenceTestRoot 'fixture.zip'
      Compress-Archive -LiteralPath (Join-Path $fixtureRoot 'Sysmon64.exe') -DestinationPath $fixtureZip
      Mock Resolve-RidePackageArtifact { [pscustomobject]@{ PackageId = 'sysmon64'; Version = '15.22'; FileName = 'Sysmon.zip'; Uri = 'https://download.sysinternals.com/files/Sysmon.zip'; ProviderDigest = $null } }
      Mock Invoke-WebRequest { Copy-Item -LiteralPath $fixtureZip -Destination $OutFile }
      Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Fixture publisher'; Issuer = 'CN=Fixture issuer'; Thumbprint = 'fixture-thumbprint' }; TimeStamperCertificate = $null } }
      Mock Start-Process { throw 'Inspection must not execute the archive member.' }
      $library = Join-Path $script:PackageEvidenceTestRoot 'sysmon-observations.json'
      $download = Save-RidePackageArtifact @{ Kind = 'Package'; PackageId = 'sysmon64'; InstallerType = 'SysmonZip' } (Join-Path $script:PackageEvidenceTestRoot 'sysmon-cache') -ObservationPath $library
      $record = (Get-Content -LiteralPath $library -Raw | ConvertFrom-Json).Observations[0]
      $record.Contents[0].ArchivePath | Should -Be 'Sysmon64.exe'
      $record.Contents[0].ParentSha256 | Should -Be $download.Sha256
      $record.Contents[0].AuthenticodeSigner | Should -Be 'CN=Fixture publisher'
      Should -Invoke Start-Process -Exactly 0
    }
  }
}

Describe 'Declared user-data preservation during removal' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $localRoot = Join-Path (Split-Path -Parent $PSScriptRoot) '.local'
      if (-not (Test-Path -LiteralPath $localRoot -PathType Container)) { $null = New-Item -ItemType Directory -Path $localRoot }
      if ((Get-Item -LiteralPath $localRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package evidence fixtures cannot use a reparse-point .local directory.' }
      $script:PackageEvidenceTestRoot = Join-Path $localRoot ('package-evidence-tests-' + [guid]::NewGuid().ToString('N'))
      $null = New-Item -ItemType Directory -Path $script:PackageEvidenceTestRoot
      $script:preservationRoot=Join-Path $script:PackageEvidenceTestRoot ([guid]::NewGuid().ToString('N'))
      New-Item -ItemType Directory -Path (Join-Path $script:preservationRoot 'Signal') -Force | Out-Null
      $script:dataFile=Join-Path $script:preservationRoot 'Signal/message-data.txt'
      [IO.File]::WriteAllText($script:dataFile,'Keep encrypted message bytes.')
      $operation=@{Name='Signal';Scope='User';InstallerType='Exe';PreserveRoamingDirectory='Signal';PreservationProcessName='Signal'}
      Mock Get-RideRoamingApplicationDataRoot { $script:preservationRoot }
      Mock Get-Process { @() }
    }
    AfterEach {
      if ([IO.Directory]::Exists($script:PackageEvidenceTestRoot)) {
        $resolvedRoot = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $script:PackageEvidenceTestRoot).Path)
        $expectedParent = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) '.local'))
        if (([IO.Path]::GetDirectoryName($resolvedRoot) -cne $expectedParent) -or
            (Split-Path -Leaf $resolvedRoot) -notmatch '^package-evidence-tests-[0-9a-f]{32}$' -or
            (([IO.File]::GetAttributes($resolvedRoot) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Refusing to clean an unexpected package evidence fixture path.' }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
      }
    }
    It 'isolates existing data from a deleting uninstaller and restores its exact contents' {
      Mock Invoke-RidePackageInstallerProcess {
        Test-Path -LiteralPath (Join-Path $script:preservationRoot 'Signal') | Should -BeFalse
        [pscustomobject]@{ExitCode=0}
      }
      (Invoke-RidePreservingPackageOperation $operation 'uninstall.exe' '/S').ExitCode | Should -Be 0
      [IO.File]::ReadAllText($script:dataFile) | Should -Be 'Keep encrypted message bytes.'
      @(Get-ChildItem -LiteralPath $script:preservationRoot -Force -Filter '.Signal.ride-preserved-*').Count | Should -Be 0
    }
    It 'returns existing data after the uninstaller throws' {
      Mock Invoke-RidePackageInstallerProcess { throw 'uninstaller failed' }
      { Invoke-RidePreservingPackageOperation $operation 'uninstall.exe' '/S' } | Should -Throw '*uninstaller failed*'
      [IO.File]::ReadAllText($script:dataFile) | Should -Be 'Keep encrypted message bytes.'
    }
    It 'does not create or adopt absent user data' {
      Remove-Item -LiteralPath $script:dataFile
      Remove-Item -LiteralPath (Join-Path $script:preservationRoot 'Signal')
      Mock Invoke-RidePackageInstallerProcess { [pscustomobject]@{ExitCode=0} }
      (Invoke-RidePreservingPackageOperation $operation 'uninstall.exe' '/S').ExitCode | Should -Be 0
      @(Get-ChildItem -LiteralPath $script:preservationRoot -Force).Count | Should -Be 0
    }
    It 'refuses reparse-point data before executing an uninstaller' {
      Mock Get-Item { [pscustomobject]@{PSIsContainer=$true;Attributes=[IO.FileAttributes]::ReparsePoint} }
      Mock Invoke-RidePackageInstallerProcess { throw 'Must not execute.' }
      { Invoke-RidePreservingPackageOperation $operation 'uninstall.exe' '/S' } | Should -Throw '*reparse-point*'
      Should -Invoke Invoke-RidePackageInstallerProcess -Exactly 0
      [IO.File]::ReadAllText($script:dataFile) | Should -Be 'Keep encrypted message bytes.'
    }
    It 'restores original data and retains a newly created destination separately' {
      Mock Invoke-RidePackageInstallerProcess {
        New-Item -ItemType Directory -Path (Join-Path $script:preservationRoot 'Signal') | Out-Null
        [IO.File]::WriteAllText((Join-Path $script:preservationRoot 'Signal/new.txt'),'new data')
        [pscustomobject]@{ExitCode=0}
      }
      (Invoke-RidePreservingPackageOperation $operation 'uninstall.exe' '/S' -WarningAction SilentlyContinue).ExitCode | Should -Be 0
      [IO.File]::ReadAllText($script:dataFile) | Should -Be 'Keep encrypted message bytes.'
      $created=@(Get-ChildItem -LiteralPath $script:preservationRoot -Directory -Force -Filter '.Signal.ride-created-*')
      $created.Count | Should -Be 1
      [IO.File]::ReadAllText((Join-Path $created[0].FullName 'new.txt')) | Should -Be 'new data'
      @(Get-ChildItem -LiteralPath $script:preservationRoot -Directory -Force -Filter '.Signal.ride-preserved-*').Count | Should -Be 0
      Test-Path -LiteralPath ($created[0].FullName+'.json') | Should -BeFalse
    }
    It 'refuses active applications and unsafe scope/path metadata before moving data' {
      Mock Invoke-RidePackageInstallerProcess { throw 'Must not run.' }
      $operation.PreserveRoamingDirectory='../Signal'
      { Invoke-RidePreservingPackageOperation $operation 'uninstall.exe' '/S' } | Should -Throw '*Invalid user-data*'
      $operation.PreserveRoamingDirectory='Signal';$operation.Scope='Machine'
      { Invoke-RidePreservingPackageOperation $operation 'uninstall.exe' '/S' } | Should -Throw '*Invalid user-data*'
      $operation.Scope='User'
      Mock Get-Process { [pscustomobject]@{Id=123} }
      { Invoke-RidePreservingPackageOperation $operation 'uninstall.exe' '/S' } | Should -Throw '*Close Signal*'
      [IO.File]::ReadAllText($script:dataFile) | Should -Be 'Keep encrypted message bytes.'
      Should -Invoke Invoke-RidePackageInstallerProcess -Exactly 0
    }
  }
}

Describe 'MSI and scoped package lifecycle' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $localRoot = Join-Path (Split-Path -Parent $PSScriptRoot) '.local'
      if (-not (Test-Path -LiteralPath $localRoot -PathType Container)) { $null = New-Item -ItemType Directory -Path $localRoot }
      if ((Get-Item -LiteralPath $localRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package evidence fixtures cannot use a reparse-point .local directory.' }
      $script:PackageEvidenceTestRoot = Join-Path $localRoot ('package-evidence-tests-' + [guid]::NewGuid().ToString('N'))
      $null = New-Item -ItemType Directory -Path $script:PackageEvidenceTestRoot
    }
    AfterEach {
      if ([IO.Directory]::Exists($script:PackageEvidenceTestRoot)) {
        $resolvedRoot = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $script:PackageEvidenceTestRoot).Path)
        $expectedParent = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) '.local'))
        if (([IO.Path]::GetDirectoryName($resolvedRoot) -cne $expectedParent) -or
            (Split-Path -Leaf $resolvedRoot) -notmatch '^package-evidence-tests-[0-9a-f]{32}$' -or
            (([IO.File]::GetAttributes($resolvedRoot) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Refusing to clean an unexpected package evidence fixture path.' }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
      }
    }
    It 'rejects a retained artifact changed after acquisition before invoking an installer' {
      $payload=Join-Path $script:PackageEvidenceTestRoot 'changed.exe';[IO.File]::WriteAllText($payload,'changed bytes')
      Mock Save-RidePackageArtifact { [pscustomobject]@{Path=$payload;Sha256=('a'*64)} }
      Mock Start-Process { throw 'Must not execute' }
      { Install-RidePackage @{Id='package.app';InstallerType='Exe'} $script:PackageEvidenceTestRoot } | Should -Throw '*SHA-256 changed*'
      Should -Invoke Start-Process -Exactly 0
    }
    It 'rejects a missing prerequisite before acquiring or starting an installer' {
      Mock Test-Path { $false }
      Mock Save-RidePackageArtifact { throw 'Must not download' }
      Mock Start-Process { throw 'Must not execute' }
      { Install-RidePackage @{ Id = 'package.git-lfs'; PrerequisitePackageId = 'package.git-for-windows'; PrerequisiteProgramFilesExecutable = 'Git\cmd\git.exe' } 'C:\cache' } | Should -Throw '*requires package.git-for-windows*'
      Should -Invoke Save-RidePackageArtifact -Exactly 0
      Should -Invoke Start-Process -Exactly 0
    }

    It 'requires a declared Windows system DLL before acquiring a package artifact' {
      $previousSystemRoot=$env:SystemRoot
      $env:SystemRoot=$script:PackageEvidenceTestRoot
      try {
        $operation=@{Id='package.imagemagick-portable-q16';PrerequisiteSystemFiles=@('vcomp140.dll')}
        Mock Save-RidePackageArtifact { throw 'Must not acquire before prerequisite validation' }
        { Install-RidePackage $operation $script:PackageEvidenceTestRoot } | Should -Throw '*requires the Windows system prerequisite*'
        Should -Invoke Save-RidePackageArtifact -Exactly 0
        $system32=Join-Path $env:SystemRoot 'System32'
        $null=New-Item -ItemType Directory -Path $system32 -Force
        [IO.File]::WriteAllText((Join-Path $system32 'vcomp140.dll'),'synthetic runtime marker')
        { Get-RidePackagePrerequisiteDirectory $operation } | Should -Not -Throw
      } finally { $env:SystemRoot=$previousSystemRoot }
    }

    It 'reports an installed but outdated minimum-version runtime without treating it as absent' {
      $operation=@{
        Id='package.runtime';InstallerType='Exe';Scope='Machine'
        DisplayNamePattern='^Example Runtime$';MinimumInstalledVersion='14.50.35710.0'
      }
      Mock Get-ItemProperty {
        [pscustomobject]@{DisplayName='Example Runtime';DisplayVersion='14.40.33810.0';UninstallString='runtime-uninstall';QuietUninstallString='runtime-quiet';InstallLocation='C:\Runtime'}
      }
      $state=Get-RideInstalledPackage -Operation $operation
      $state.Present | Should -BeFalse
      $state.DisplayVersion | Should -Be '14.40.33810.0'
      $state.DisplayName | Should -Be 'Example Runtime'
    }

    It 'makes a newly installed prerequisite visible and restores PATH after installer failure' {
      Mock Test-Path { $true }
      Mock Start-Process { $env:PATH | Should -BeLike '*Git\cmd;*'; throw 'Installer failure' }
      $original = $env:PATH
      { Invoke-RidePackageInstallerProcess @{ Id = 'package.git-lfs'; PrerequisitePackageId = 'package.git-for-windows'; PrerequisiteProgramFilesExecutable = 'Git\cmd\git.exe' } 'C:\cache\lfs.exe' '/S' } | Should -Throw '*Installer failure*'
      $env:PATH | Should -BeExactly $original
    }
    It 'invokes MSI installation quietly and recognizes the declared reboot result' {
      Mock Save-RidePackageArtifact { [pscustomobject]@{ Path = 'C:\cache\Example x64.msi' } }
      Mock Start-Process { [pscustomobject]@{ ExitCode = 3010 } }
      Mock Get-RideInstalledPackage { [pscustomobject]@{ Present = $true } }
      Install-RidePackage @{ Id = 'package.example'; Name = 'Example'; InstallerType = 'Msi'; InstallerArguments = '/qn /norestart'; SuccessExitCodes = @(0, 3010) } 'C:\cache' -WarningAction SilentlyContinue
      Should -Invoke Start-Process -Exactly 1 -ParameterFilter { $FilePath -like '*msiexec.exe' -and $ArgumentList -eq '/i "C:\cache\Example x64.msi" /qn /norestart' }
    }

    It 'changes registered MSI maintenance to removal and verifies absence' {
      $script:detectionCount = 0
      Mock Get-RideInstalledPackage {
        $script:detectionCount++
        [pscustomobject]@{ Present = $script:detectionCount -eq 1; DisplayName = 'Example'; UninstallString = 'MsiExec.exe /I{11111111-1111-1111-1111-111111111111}'; QuietUninstallString = $null }
      }
      Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }
      Uninstall-RidePackage @{ Id = 'package.example'; Name = 'Example'; InstallerType = 'Msi'; UninstallerArguments = '/qn /norestart'; SuccessExitCodes = @(0, 3010) }
      Should -Invoke Start-Process -Exactly 1 -ParameterFilter { $ArgumentList -eq '/X{11111111-1111-1111-1111-111111111111} /qn /norestart' }
    }

    It 'uses the declared EXE uninstaller for an MSI wrapper and verifies absence' {
      $script:detectionCount = 0
      Mock Get-RideInstalledPackage {
        $script:detectionCount++
        [pscustomobject]@{ Present = $script:detectionCount -eq 1; DisplayName = 'Mozilla Firefox'; UninstallString = '"C:\Program Files\Mozilla Firefox\uninstall\helper.exe"'; QuietUninstallString = $null }
      }
      Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }
      Uninstall-RidePackage @{ Id = 'package.firefox'; Name = 'Mozilla Firefox'; InstallerType = 'Msi'; UninstallerType = 'Exe'; UninstallerArguments = '/S' }
      Should -Invoke Start-Process -Exactly 1 -ParameterFilter { $FilePath -eq 'C:\Program Files\Mozilla Firefox\uninstall\helper.exe' -and $ArgumentList -eq '/S' }
    }

    It 'refuses an unexpected EXE uninstaller for a native MSI package' {
      Mock Get-RideInstalledPackage { [pscustomobject]@{ Present = $true; DisplayName = 'Example'; UninstallString = '"C:\Example\helper.exe"'; QuietUninstallString = $null } }
      Mock Start-Process { throw 'Must not execute' }
      { Uninstall-RidePackage @{ Id = 'package.example'; Name = 'Example'; InstallerType = 'Msi'; UninstallerArguments = '/qn /norestart' } } | Should -Throw '*registered msiexec*'
      Should -Invoke Start-Process -Exactly 0
    }

    It 'does not treat a machine installation as current-user package presence' {
      Mock Get-ItemProperty { @() }
      $current = Get-RideInstalledPackage @{ Scope = 'User'; DisplayNamePattern = '^Example$' }
      $current.Present | Should -BeFalse
      Should -Invoke Get-ItemProperty -Exactly 1 -ParameterFilter { $Path -like 'HKCU:*' }
      Should -Invoke Get-ItemProperty -Exactly 0 -ParameterFilter { $Path -like 'HKLM:*' }
    }

    It 'detects stable Signal versioned registration without accepting the Beta edition' {
      Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.CatalogData.psm1') -Force -Scope Local
      $signalPattern = ((Import-RideCatalogData (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')).Operations | Where-Object Id -eq 'package.signal').DisplayNamePattern
      Mock Get-ItemProperty {
        @(
          [pscustomobject]@{DisplayName='Signal Beta 8.31.0';DisplayVersion='8.31.0';UninstallString='beta.exe';QuietUninstallString=$null;InstallLocation='C:\Beta'},
          [pscustomobject]@{DisplayName='Signal 8.30.0';DisplayVersion='8.30.0';UninstallString='signal.exe';QuietUninstallString=$null;InstallLocation='C:\Signal'}
        )
      }
      $current = Get-RideInstalledPackage @{Scope='User';DisplayNamePattern=$signalPattern}
      $current.Present | Should -BeTrue
      $current.DisplayName | Should -Be 'Signal 8.30.0'
      $current.DisplayVersion | Should -Be '8.30.0'
      $current.UninstallString | Should -Be 'signal.exe'
    }

    It 'fails an MSI installer error without accepting detection alone' {
      Mock Save-RidePackageArtifact { [pscustomobject]@{ Path = 'C:\cache\example.msi' } }
      Mock Start-Process { [pscustomobject]@{ ExitCode = 1603 } }
      Mock Get-RideInstalledPackage { [pscustomobject]@{ Present = $true } }
      { Install-RidePackage @{ Id = 'package.example'; Name = 'Example'; InstallerType = 'Msi'; InstallerArguments = '/qn /norestart'; SuccessExitCodes = @(0, 3010) } 'C:\cache' } | Should -Throw '*1603*'
      Should -Invoke Get-RideInstalledPackage -Exactly 0
    }
  }
}
