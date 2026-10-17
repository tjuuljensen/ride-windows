<#
.SYNOPSIS
  Verify the pending Wireshark MSI selection and mocked installer boundaries.
.DESCRIPTION
  Uses catalog metadata, inert fixture bytes and mocked registry/process/download
  calls. No installer, driver, association or live package discovery is executed.
.EXAMPLE
  Invoke-Pester .\tests\WiresharkPackage.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture; native acceptance remains pending.
#>
BeforeDiscovery {
  $root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE-Packages.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
}
BeforeAll {
  $script:WiresharkOperation=(Import-RideCatalogData -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')).Operations|Where-Object Id -eq package.wireshark
}
Describe 'Wireshark machine MSI candidate' {
  It 'retains pending targets and is absent from every default or optional profile' {
    $WiresharkOperation.PendingAcceptance|Should -BeTrue
    $WiresharkOperation.SupportedTargets.Count|Should -Be 0
    $WiresharkOperation.TargetDefaults.Count|Should -Be 0
    $WiresharkOperation.Scope|Should -Be Machine
    $WiresharkOperation.RequiresAdmin|Should -BeTrue
    foreach($file in Get-ChildItem -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'profiles') -Filter '*.psd1'){
      [IO.File]::ReadAllText($file.FullName)|Should -Not -Match 'package\.wireshark'
    }
  }
  It 'resolves the pinned publisher MSI without discovery or an executable wrapper' {
    $artifact=Resolve-RidePackageArtifact -Operation $WiresharkOperation
    $artifact.Version|Should -BeExactly '4.6.9'
    $artifact.FileName|Should -BeExactly 'Wireshark-4.6.9-x64.msi'
    $artifact.Uri|Should -BeExactly $WiresharkOperation.DownloadUri
    $artifact.ProviderDigest|Should -BeExactly ('sha256:'+$WiresharkOperation.ExpectedSha256)
    $WiresharkOperation.InstallerArguments|Should -BeExactly '/qn /norestart WIRESHARK_FILE_EXTENSIONS=0'
    $WiresharkOperation.LicenseUri|Should -Match '^https://gitlab.com/wireshark/wireshark/'
  }
  It 'has reviewed exact-byte source evidence and does not claim runtime or PGP acceptance' {
    $record=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'docs/archive/evidence/wireshark-msi-source-review-2026-10-17.json') -Raw|ConvertFrom-Json
    $record.Executed|Should -BeFalse
    $record.Observation.Sha256|Should -BeExactly $WiresharkOperation.ExpectedSha256
    $record.Observation.AuthenticodeStatus|Should -BeExactly 'Valid'
    $record.PublisherHash.Match|Should -BeTrue
    $record.PublisherHash.PgpSignatureVerified|Should -BeFalse
    $record.Msi.AssociationComponentCount|Should -Be 29
    $record.Msi.ConditionedClassRegistryRows|Should -Be 116
    $record.Msi.AssociationCondition|Should -BeExactly 'WIRESHARK_FILE_EXTENSIONS = "1"'
    $record.Msi.Template|Should -BeExactly 'x64;1033'
    $record.Msi.CaptureDriverFileCount|Should -Be 0
  }
}
Describe 'Wireshark mocked shared installer dispatch' {
  BeforeEach {
    $script:operation=$WiresharkOperation.Clone()
    $script:payload=Join-Path $TestDrive 'inert-wireshark.msi'
    [IO.File]::WriteAllText($payload,'inert MSI stand-in; never execute')
    $script:artifact=[pscustomobject]@{Path=$payload;Version='4.6.9';Sha256=(Get-FileHash -LiteralPath $payload).Hash}
    Mock Get-RidePackageConfiguration -ModuleName RIDE.PackageSelection {@{}}
    Mock Assert-RidePackageExecutionContext -ModuleName RIDE-Packages {}
    Mock Get-RidePackagePrerequisiteDirectory -ModuleName RIDE-Packages {$null}
    Mock Save-RidePackageArtifact -ModuleName RIDE-Packages {$script:artifact}
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages {[pscustomobject]@{ExitCode=0}}
    Mock Get-RideInstalledPackage -ModuleName RIDE-Packages {[pscustomobject]@{Present=$true}}
    Mock Start-Process -ModuleName RIDE-Packages {throw 'No process may start in this fixture.'}
  }
  It 'uses system msiexec with explicit no-association and no-restart arguments' {
    $null=Install-RidePackage -Operation $operation -CacheDirectory $TestDrive
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Times 1 -Exactly -ParameterFilter {
      $FilePath -eq (Join-Path $env:SystemRoot 'System32\msiexec.exe') -and $ArgumentList -match '^/i ".*inert-wireshark\.msi" /qn /norestart WIRESHARK_FILE_EXTENSIONS=0$'
    }
    Should -Invoke Start-Process -ModuleName RIDE-Packages -Times 0 -Exactly
  }
  It 'reports reboot required without starting a reboot or nested driver installer' {
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages {[pscustomobject]@{ExitCode=3010}}
    $null=Install-RidePackage -Operation $operation -CacheDirectory $TestDrive -WarningAction SilentlyContinue
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Times 1 -Exactly
    Should -Invoke Start-Process -ModuleName RIDE-Packages -Times 0 -Exactly
  }
  It 'retains failed artifacts and refuses false installed-state success' {
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages {[pscustomobject]@{ExitCode=1603}}
    {Install-RidePackage $operation $TestDrive}|Should -Throw '*1603*'
    Test-Path -LiteralPath $payload|Should -BeTrue
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages {[pscustomobject]@{ExitCode=0}}
    Mock Get-RideInstalledPackage -ModuleName RIDE-Packages {[pscustomobject]@{Present=$false}}
    {Install-RidePackage $operation $TestDrive}|Should -Throw '*not detected*'
  }
  It 'refuses artifact drift before invoking any process' {
    $script:artifact.Sha256='0'*64
    {Install-RidePackage $operation $TestDrive}|Should -Throw '*SHA-256 changed*'
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Times 0 -Exactly
  }
  It 'removes only its registered MSI product and never silently runs an NSIS remover' {
    $script:presenceCalls=0
    Mock Get-RideInstalledPackage -ModuleName RIDE-Packages {
      $script:presenceCalls++
      [pscustomobject]@{Present=($script:presenceCalls -eq 1);UninstallString='MsiExec.exe /I{B9717009-0193-4E75-A6F4-A4B95F2856A9}';DisplayName='Wireshark'}
    }
    Uninstall-RidePackage $operation
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Times 1 -Exactly -ParameterFilter {
      $FilePath -eq 'MsiExec.exe' -and $ArgumentList -eq '/X{B9717009-0193-4E75-A6F4-A4B95F2856A9} /qn /norestart'
    }
    Mock Get-RideInstalledPackage -ModuleName RIDE-Packages {[pscustomobject]@{Present=$true;UninstallString='"C:\Program Files\Wireshark\uninstall.exe"';DisplayName='Wireshark'}}
    {Uninstall-RidePackage $operation}|Should -Throw '*MSI removal requires*'
  }
}
