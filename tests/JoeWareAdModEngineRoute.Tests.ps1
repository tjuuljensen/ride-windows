<#
.SYNOPSIS
  Validate the RIDE package-handler route for offline portable AdMod artifacts.
.DESCRIPTION
  Uses an inert ZIP entry and an optional retained publisher archive to exercise
  verified artifact retention and Install-RidePackage through the real portable
  staging handler. It mocks machine elevation validation and never executes
  AdMod, changes Windows state or inspects Defender.
.EXAMPLE
  Invoke-Pester .\tests\JoeWareAdModEngineRoute.Tests.ps1
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  The test validates handler routing, not Windows target acceptance.
#>
BeforeDiscovery {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-Packages.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
}

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-Packages.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
}

Describe 'JoeWare AdMod engine package-handler route' {
  InModuleScope RIDE-Packages {
    It 'passes a verified offline artifact through the real portable handler without network acquisition' {
      Add-Type -AssemblyName System.IO.Compression
      Add-Type -AssemblyName System.IO.Compression.FileSystem

      $fixtureBase = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../.local/application-package-tests'))
      $null = New-Item -ItemType Directory -Path $fixtureBase -Force
      $caseName = 'joeware-admod-engine-route-' + [guid]::NewGuid().ToString('N')
      $caseRoot = [IO.Path]::GetFullPath((Join-Path $fixtureBase $caseName))
      if (Test-Path -LiteralPath $caseRoot) { throw 'Unique AdMod engine-route fixture already exists.' }
      $null = New-Item -ItemType Directory -Path $caseRoot
      $tempRoot = Join-Path $caseRoot 'temp'
      $null = New-Item -ItemType Directory -Path $tempRoot
      $previousTemp = $env:TEMP
      $previousTmp = $env:TMP
      $casePassed = $false
      try {
        $env:TEMP = $tempRoot
        $env:TMP = $tempRoot
        $archivePath = Join-Path $caseRoot 'admod-inert.zip'
        $zip = [IO.Compression.ZipFile]::Open($archivePath, [IO.Compression.ZipArchiveMode]::Create)
        try {
          $writer = [IO.StreamWriter]::new($zip.CreateEntry('AdMod.exe').Open())
          try { $writer.Write('inert test fixture; never executable') } finally { $writer.Dispose() }
        } finally { $zip.Dispose() }
        $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $operation = @{
          PackageId = 'joeware-admod'
          Scope = 'Machine'
          RequiresAdmin = $true
          InstallerType = 'Portable'
          PortableFormat = 'Zip'
          PackageVersion = '1.29.00'
          ExpectedSha256 = $hash
          PortableMembers = @('AdMod.exe')
          RequiredFiles = @('AdMod.exe')
          ResolvedToolsDirectory = Join-Path $caseRoot 'tools'
          InstallDirectory = Join-Path (Join-Path $caseRoot 'tools') 'joeware-admod'
          SelectedVariant = 'portable'
        }
        $artifact = [pscustomobject]@{
          Path = $archivePath
          Sha256 = $hash
          Version = '1.29.00'
          InstallerType = 'Portable'
          Offline = $true
          OfflineCapability = 'DeclaredNoNetwork'
        }

        Mock Resolve-RidePackageSelection { $Operation }
        Mock Assert-RidePackageExecutionContext {}
        Mock Save-RidePackageArtifact { throw 'Offline routing must not acquire from JoeWare.' }

        $result = Install-RidePackage -Operation $operation -CacheDirectory (Join-Path $caseRoot 'unused-cache') -OfflineArtifact $artifact

        $result.Path | Should -BeExactly $archivePath
        (Get-RidePortableState -Operation $operation).Healthy | Should -BeTrue
        [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'AdMod.exe')) | Should -BeExactly 'inert test fixture; never executable'
        Should -Invoke Assert-RidePackageExecutionContext -Exactly 1 -ParameterFilter { $Operation.PackageId -ceq 'joeware-admod' }
        Should -Invoke Save-RidePackageArtifact -Exactly 0
        $casePassed = $true
      } finally {
        $env:TEMP = $previousTemp
        $env:TMP = $previousTmp
        if ($casePassed) {
          $expectedPrefix = $fixtureBase.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
          if (-not $caseRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
              (Split-Path -Leaf $caseRoot) -cne $caseName -or $caseName -notmatch '^joeware-admod-engine-route-[0-9a-f]{32}$') {
            throw 'Refusing to clean AdMod engine-route fixture outside its unique workspace root.'
          }
          Remove-Item -LiteralPath $caseRoot -Recurse -Force
        }
      }
    }

    It 'validates a retained publisher archive in the managed cache and stages only the declared member' {
      $fixtureDirectory = [Environment]::GetEnvironmentVariable('RIDE_ADMOD_FIXTURE_DIRECTORY')
      if ([string]::IsNullOrWhiteSpace($fixtureDirectory)) {
        Set-ItResult -Skipped -Because 'Set RIDE_ADMOD_FIXTURE_DIRECTORY to the retained AdMod publisher archive directory to enable this check.'
        return
      }

      $sourceArchive = Join-Path $fixtureDirectory 'AdMod.zip'
      if (-not (Test-Path -LiteralPath $sourceArchive -PathType Leaf)) { throw 'The retained AdMod ZIP was not found.' }
      $fixtureBase = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../.local/application-package-tests'))
      $null = New-Item -ItemType Directory -Path $fixtureBase -Force
      $caseName = 'joeware-admod-managed-cache-' + [guid]::NewGuid().ToString('N')
      $caseRoot = [IO.Path]::GetFullPath((Join-Path $fixtureBase $caseName))
      if (Test-Path -LiteralPath $caseRoot) { throw 'Unique AdMod managed-cache fixture already exists.' }
      $null = New-Item -ItemType Directory -Path $caseRoot
      $previousTemp = $env:TEMP
      $previousTmp = $env:TMP
      $casePassed = $false
      try {
        $tempRoot = Join-Path $caseRoot 'temp'
        $null = New-Item -ItemType Directory -Path $tempRoot
        $env:TEMP = $tempRoot
        $env:TMP = $tempRoot

        $sourceHash = (Get-FileHash -LiteralPath $sourceArchive -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $sourceHash | Should -BeExactly '45cf050eec76d7f1c736b613616bcbf4c3dea872d3d5f7398fd276b1fc369235'
        $cacheRoot = Join-Path $caseRoot 'cache'
        $cachedDirectory = Join-Path (Join-Path $cacheRoot 'joeware-admod') '1.29.00'
        $null = New-Item -ItemType Directory -Path $cachedDirectory -Force
        $cachedArchive = Join-Path $cachedDirectory 'AdMod.zip'
        Copy-Item -LiteralPath $sourceArchive -Destination $cachedArchive -ErrorAction Stop

        $toolsDirectory = Join-Path $caseRoot 'tools'
        $operation = @{
          Id = 'package.joeware-admod'
          Kind = 'Package'
          PackageId = 'joeware-admod'
          Name = 'JoeWare AdMod (portable)'
          Scope = 'Machine'
          RequiresAdmin = $true
          InstallerType = 'Portable'
          PortableFormat = 'Zip'
          PackageVersion = '1.29.00'
          ExpectedSha256 = $sourceHash
          Architecture = 'x86'
          DownloadProvider = 'JoeWareAdModForm'
          AcquisitionProduct = 'admod'
          ProductUri = 'https://www.joeware.net/freetools/tools/admod/index.htm'
          DownloadUri = 'https://www.joeware.net/freetools/tools/admod/index.htm'
          AssetName = 'AdMod.zip'
          License = 'Proprietary freeware; exact-version review is administrative.'
          LicenseUri = 'https://www.joeware.net/freetools/tools/admod/index.htm'
          TermsUri = 'https://www.joeware.net/freetools/warranty.htm'
          PortableMembers = @('AdMod.exe')
          RequiredFiles = @('AdMod.exe')
          SelectedVariant = 'portable'
          ResolvedToolsDirectory = $toolsDirectory
          InstallDirectory = Join-Path $toolsDirectory 'joeware-admod'
        }
        $observationPath = Join-Path $caseRoot 'artifact-observations.json'

        Mock Resolve-RidePackageSelection { $Operation }
        Mock Assert-RidePackageExecutionContext {}
        Mock Invoke-WebRequest { throw 'The retained cache test must not request the network.' }
        $artifact = Save-RidePackageArtifact -Operation $operation -DestinationDirectory $cacheRoot -ObservationPath $observationPath

        $artifact.Path | Should -BeExactly $cachedArchive
        $artifact.Sha256 | Should -BeExactly $sourceHash
        $artifact.ProviderDigest | Should -BeExactly ('sha256:' + $sourceHash)
        $artifactObservation = Get-Content -LiteralPath ($cachedArchive + '.ride.json') -Raw | ConvertFrom-Json
        $artifactObservation.AcquisitionKind | Should -BeExactly 'Cache'
        $artifactObservation.Sha256 | Should -BeExactly $sourceHash
        (Test-Path -LiteralPath ($cachedArchive + '.ride.json') -PathType Leaf) | Should -BeTrue
        $sharedObservation = Get-Content -LiteralPath $observationPath -Raw | ConvertFrom-Json
        $sharedObservation.Observations.Count | Should -Be 1
        $sharedObservation.Observations[0].AcquisitionKind | Should -BeExactly 'Cache'

        $artifact | Add-Member -NotePropertyName Offline -NotePropertyValue $true -Force
        $artifact | Add-Member -NotePropertyName OfflineCapability -NotePropertyValue 'DeclaredNoNetwork' -Force
        $artifact | Add-Member -NotePropertyName InstallerType -NotePropertyValue 'Portable' -Force
        $result = Install-RidePackage -Operation $operation -CacheDirectory $cacheRoot -OfflineArtifact $artifact
        $result.Path | Should -BeExactly $cachedArchive
        (Get-RidePortableState -Operation $operation).Healthy | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'AdMod.exe') -PathType Leaf) | Should -BeTrue
        Should -Invoke Invoke-WebRequest -Exactly 0
        Should -Invoke Assert-RidePackageExecutionContext -Exactly 1 -ParameterFilter { $Operation.PackageId -ceq 'joeware-admod' }
        $casePassed = $true
      } finally {
        $env:TEMP = $previousTemp
        $env:TMP = $previousTmp
        if ($casePassed) {
          $expectedPrefix = $fixtureBase.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
          if (-not $caseRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
              (Split-Path -Leaf $caseRoot) -cne $caseName -or $caseName -notmatch '^joeware-admod-managed-cache-[0-9a-f]{32}$') {
            throw 'Refusing to clean AdMod managed-cache fixture outside its unique workspace root.'
          }
          Remove-Item -LiteralPath $caseRoot -Recurse -Force
        }
      }
    }
  }
}
