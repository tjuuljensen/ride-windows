<#
.SYNOPSIS
  Verify acquisition evidence and publisher checksum handling without installers.
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
}

Describe 'Publisher evidence and acquisition provenance' {
  InModuleScope RIDE-Packages {
    It 'rejects release assets from a mirror or a different GitHub project' {
      Mock Invoke-RestMethod {
        [pscustomobject]@{ tag_name = '1.0'; assets = @([pscustomobject]@{ name = 'app.exe'; browser_download_url = $script:untrustedAssetUri }) }
      }
      foreach ($uri in @('https://mirror.example.org/app.exe', 'https://github.com/other/project/releases/download/1.0/app.exe', 'https://github.com/publisher/project-other/releases/download/1.0/app.exe')) {
        $script:untrustedAssetUri = $uri
        { Resolve-RidePackageArtifact @{ PackageId = 'app'; DownloadProvider = 'GitHubReleaseApi'; DownloadUri = 'https://api.github.com/repos/publisher/project/releases/latest'; AssetPattern = '^app.exe$'; Architecture = 'x64' } } | Should -Throw '*declared publisher repository*'
      }
    }

    It 'reads the exact installer checksum from publisher release notes' {
      Mock Invoke-RestMethod {
        [pscustomobject]@{ tag_name = 'v2.56.0.windows.2'; html_url = 'https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.2'; body = '| Git-2.56.0.2-64-bit.exe | ' + ('a' * 64) + ' |'; assets = @([pscustomobject]@{ name = 'Git-2.56.0.2-64-bit.exe'; browser_download_url = 'https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/Git-2.56.0.2-64-bit.exe'; digest = $null }) }
      }
      $operation = @{ PackageId = 'git-for-windows'; DownloadProvider = 'GitHubReleaseApi'; DownloadUri = 'https://api.github.com/repos/git-for-windows/git/releases/latest'; AssetPattern = '^Git-\d+(?:\.\d+){2,3}-64-bit\.exe$'; Architecture = 'x64'; PublisherChecksumSource = 'ReleaseNotes' }
      $resolved = Resolve-RidePackageArtifact $operation
      $resolved.PublisherSha256 | Should -Be ('a' * 64)
      $resolved.ProviderDigest | Should -BeNullOrEmpty
    }

    It 'rejects conflicting checksum evidence for the selected filename' {
      Mock Invoke-RestMethod {
        [pscustomobject]@{ tag_name = 'v1'; html_url = 'https://github.com/example/app/releases/tag/v1'; body = ('a' * 64) + " app.exe`n" + ('b' * 64) + ' app.exe'; assets = @([pscustomobject]@{ name = 'app.exe'; browser_download_url = 'https://github.com/example/app/releases/download/v1/app.exe' }) }
      }
      $operation = @{ PackageId = 'app'; DownloadProvider = 'GitHubReleaseApi'; DownloadUri = 'https://api.github.com/repos/example/app/releases/latest'; AssetPattern = '^app\.exe$'; PublisherChecksumSource = 'ReleaseNotes' }
      { Resolve-RidePackageArtifact $operation } | Should -Throw '*Conflicting publisher checksums*'
    }

    It 'retains a sidecar and distinguishes a cached observation from a download' {
      $destination = Join-Path $TestDrive 'artifacts'
      $library = Join-Path $TestDrive 'observations.json'
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
      Mock Resolve-RidePackageArtifact { [pscustomobject]@{ PackageId = 'app'; Version = '1'; FileName = 'app.exe'; Uri = 'https://example.org/app.exe'; ProviderDigest = $null; PublisherSha256 = 'a' * 64 } }
      Mock Invoke-WebRequest { 'different bytes' | Set-Content -LiteralPath $OutFile }
      Mock Add-RideArtifactObservation { }
      { Save-RidePackageArtifact @{ Kind = 'Package'; PackageId = 'app' } (Join-Path $TestDrive 'mismatch') -ObservationPath (Join-Path $TestDrive 'mismatch.json') } | Should -Throw '*Publisher SHA-256 checksum mismatch*'
      Should -Invoke Add-RideArtifactObservation -Exactly 0
    }

    It 'binds Sysmon executable evidence to its parent archive before installation' {
      $fixtureRoot = Join-Path $TestDrive 'archive-source'
      New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
      'mock executable' | Set-Content -LiteralPath (Join-Path $fixtureRoot 'Sysmon64.exe')
      $fixtureZip = Join-Path $TestDrive 'fixture.zip'
      Compress-Archive -LiteralPath (Join-Path $fixtureRoot 'Sysmon64.exe') -DestinationPath $fixtureZip
      Mock Resolve-RidePackageArtifact { [pscustomobject]@{ PackageId = 'sysmon64'; Version = '15.22'; FileName = 'Sysmon.zip'; Uri = 'https://download.sysinternals.com/files/Sysmon.zip'; ProviderDigest = $null } }
      Mock Invoke-WebRequest { Copy-Item -LiteralPath $fixtureZip -Destination $OutFile }
      Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Fixture publisher'; Issuer = 'CN=Fixture issuer'; Thumbprint = 'fixture-thumbprint' }; TimeStamperCertificate = $null } }
      Mock Start-Process { throw 'Inspection must not execute the archive member.' }
      $library = Join-Path $TestDrive 'sysmon-observations.json'
      $download = Save-RidePackageArtifact @{ Kind = 'Package'; PackageId = 'sysmon64'; InstallerType = 'SysmonZip' } (Join-Path $TestDrive 'sysmon-cache') -ObservationPath $library
      $record = (Get-Content -LiteralPath $library -Raw | ConvertFrom-Json).Observations[0]
      $record.Contents[0].ArchivePath | Should -Be 'Sysmon64.exe'
      $record.Contents[0].ParentSha256 | Should -Be $download.Sha256
      $record.Contents[0].AuthenticodeSigner | Should -Be 'CN=Fixture publisher'
      Should -Invoke Start-Process -Exactly 0
    }
  }
}

Describe 'MSI and scoped package lifecycle' {
  InModuleScope RIDE-Packages {
    It 'rejects a missing prerequisite before acquiring or starting an installer' {
      Mock Test-Path { $false }
      Mock Save-RidePackageArtifact { throw 'Must not download' }
      Mock Start-Process { throw 'Must not execute' }
      { Install-RidePackage @{ Id = 'package.git-lfs'; PrerequisitePackageId = 'package.git-for-windows'; PrerequisiteProgramFilesExecutable = 'Git\cmd\git.exe' } 'C:\cache' } | Should -Throw '*requires package.git-for-windows*'
      Should -Invoke Save-RidePackageArtifact -Exactly 0
      Should -Invoke Start-Process -Exactly 0
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

    It 'does not treat a machine installation as current-user package presence' {
      Mock Get-ItemProperty { @() }
      $current = Get-RideInstalledPackage @{ Scope = 'User'; DisplayNamePattern = '^Example$' }
      $current.Present | Should -BeFalse
      Should -Invoke Get-ItemProperty -Exactly 1 -ParameterFilter { $Path -like 'HKCU:*' }
      Should -Invoke Get-ItemProperty -Exactly 0 -ParameterFilter { $Path -like 'HKLM:*' }
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
