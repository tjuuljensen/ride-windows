<#
.SYNOPSIS
  Inspect package presence, retain upstream artifacts, and run catalog installers.

.DESCRIPTION
  Queries uninstall entries or the Sysmon service. Resolves GitHub release/file revisions or the
  Microsoft Sysmon archive; downloads versioned artifacts, checks available provider digests, and
  records SHA-256/Authenticode observations. Install/uninstall run declared commands and check
  presence; hashes alone are not publisher authentication.

.EXAMPLE
  Import-Module .\modules\RIDE-Packages.psm1
  Import definitions; inspect exported commands with Get-Help before use.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return the types documented in their individual help.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Windows CIM/registry/file APIs; upstream HTTPS access; elevation as declared by the
  engine.
  File/environment inputs: Catalog package/artifact metadata, cache/destination paths, and
  catalog/artifact-observations.json (or an artifact sidecar on shared-record failure).
  Recovery: State-changing handlers are engine-internal: use ride.ps1 preview and captured-run
  restoration. Direct calls bypass ShouldProcess and snapshot capture.
  Author: RIDE-Windows maintainers.
  Version: 0.2.0
  Changelog:
    0.2.0: Retain publisher checksums, archive-member signatures and acquisition provenance.
    0.1.0: Establish documented module ownership, version, and exported-command help during this
    walkthrough.
  Supported targets are declared per operation in catalog/operations.psd1. This walkthrough
  validates syntax/help, not Windows state transitions.

.LINK
  docs/models/script-repository-model.md

.LINK
  docs/OPERATIONS.md

#>


$script:ModuleVersion = '0.2.0'

function Get-RideInstalledPackage {
  <#
  .SYNOPSIS
    Inspect declared package presence and uninstall metadata.

  .DESCRIPTION
    Queries scope-matched uninstall entries using DisplayNamePattern, or the Sysmon service for SysmonZip.
    Returns the first detected match and registered metadata without installation/removal.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideInstalledPackage -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Present, DisplayName, DisplayVersion, uninstall
    strings, and InstallLocation.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  if ($Operation.InstallerType -eq 'SysmonZip') {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sysmon64'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($service) {
      $exe = [regex]::Match([string]$service.PathName, '^\s*"?(?<path>[^" ]+\.exe)').Groups['path'].Value
      if (-not $exe) { throw "The installed Sysmon service '$($service.Name)' has an unrecognized executable path." }
      $version = if (Test-Path -LiteralPath $exe -PathType Leaf) { [Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion } else { $null }
      return [pscustomobject]@{ Present = $true; DisplayName = 'Sysmon'; DisplayVersion = $version; UninstallString = '"' + $exe + '"'; QuietUninstallString = $null; InstallLocation = Split-Path -Parent $exe }
    }
    return [pscustomobject]@{ Present = $false; DisplayName = $null; DisplayVersion = $null; UninstallString = $null; QuietUninstallString = $null; InstallLocation = $null }
  }

  $uninstallRoots = if ($Operation.Scope -eq 'User') { @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') } else { @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  ) }
  foreach ($root in $uninstallRoots) {
    foreach ($entry in (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
      if ($entry.DisplayName -match $Operation.DisplayNamePattern) {
        return [pscustomobject]@{
          Present = $true
          DisplayName = $entry.DisplayName
          DisplayVersion = $entry.DisplayVersion
          UninstallString = $entry.UninstallString
          QuietUninstallString = $entry.QuietUninstallString
          InstallLocation = $entry.InstallLocation
        }
      }
    }
  }

  [pscustomobject]@{ Present = $false; DisplayName = $null; DisplayVersion = $null; UninstallString = $null; QuietUninstallString = $null; InstallLocation = $null }
}

function Get-RideSysmonInstallRoot {
  Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RIDE/Programs/Sysmon'
}

function Resolve-RidePackageArtifact {
  <#
  .SYNOPSIS
    Resolve the catalog source to a versioned upstream artifact.

  .DESCRIPTION
    Queries an allowed GitHub release API, immutable GitHub file commit, or Microsoft Sysmon page.
    Validates source/asset metadata and returns available digest/signature links. Makes network
    requests but does not download/install the artifact.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Resolve-RidePackageArtifact -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Version, FileName, Uri, source/provenance,
    architecture, and available digest/reference metadata.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  if ($Operation.DownloadProvider -eq 'SysinternalsSysmonPage') {
    if (-not [uri]::IsWellFormedUriString([string]$Operation.VersionUri, [UriKind]::Absolute) -or ([uri]$Operation.VersionUri).Scheme -ne 'https' -or ([uri]$Operation.VersionUri).Host -ne 'learn.microsoft.com') { throw 'Sysmon version discovery must use its Microsoft Learn HTTPS page.' }
    if (-not [uri]::IsWellFormedUriString([string]$Operation.DownloadUri, [UriKind]::Absolute) -or ([uri]$Operation.DownloadUri).Scheme -ne 'https' -or ([uri]$Operation.DownloadUri).Host -ne 'download.sysinternals.com') { throw 'Sysmon downloads must use Microsoft Sysinternals HTTPS hosting.' }
    $page = Invoke-WebRequest -Uri $Operation.VersionUri -UseBasicParsing -ErrorAction Stop
    $versionMatch = [regex]::Match([string]$page.Content, '(?is)<h1[^>]*>\s*Sysmon\s+v(?<version>\d+(?:\.\d+)+)')
    if (-not $versionMatch.Success) { $versionMatch = [regex]::Match([string]$page.Content, '(?i)Sysmon\s+v(?<version>\d+(?:\.\d+)+)') }
    if (-not $versionMatch.Success) { throw 'Could not resolve the current Sysmon version from the Microsoft download page.' }
    return [pscustomobject]@{
      PackageId = [string]$Operation.PackageId
      OriginUri = [string]$Operation.ProductUri
      Version = $versionMatch.Groups['version'].Value
      Architecture = [string]$Operation.Architecture
      FileName = [string]$Operation.AssetName
      Uri = [string]$Operation.DownloadUri
      SourceUri = [string]$Operation.VersionUri
      ProviderDigest = $null
      ChecksumUris = @()
      SignatureUris = @()
    }
  }

  if ($Operation.DownloadProvider -eq 'GitHubFileCommitApi') {
    if (-not [uri]::IsWellFormedUriString([string]$Operation.DownloadUri, [UriKind]::Absolute) -or ([uri]$Operation.DownloadUri).Scheme -ne 'https' -or ([uri]$Operation.DownloadUri).Host -ne 'api.github.com') {
      throw "The GitHub file history API URI for $($Operation.ArtifactId) must use HTTPS on api.github.com."
    }
    $commits = @(Invoke-RestMethod -Uri $Operation.DownloadUri -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'RIDE-Windows' } -ErrorAction Stop)
    if ($commits.Count -lt 1 -or [string]$commits[0].sha -notmatch '^[0-9a-fA-F]{40}$') { throw "No immutable file revision was returned for $($Operation.ArtifactId)." }
    $pathParts = @(([string]$Operation.AssetPath) -split '/')
    if (-not $Operation.AssetPath -or @($pathParts | Where-Object { $_ -in @('', '.', '..') -or $_ -match '[\\:]' }).Count -gt 0) { throw "Invalid artifact path for $($Operation.ArtifactId)." }
    $sha = ([string]$commits[0].sha).ToLowerInvariant()
    $encodedPath = ($pathParts | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
    return [pscustomobject]@{
      PackageId = [string]$Operation.ArtifactId
      ArtifactId = [string]$Operation.ArtifactId
      OriginUri = [string]$Operation.ProductUri
      Version = $sha
      Architecture = [string]$Operation.Architecture
      FileName = [IO.Path]::GetFileName([string]$Operation.AssetPath)
      Uri = "https://raw.githubusercontent.com/$($Operation.Repository)/$sha/$encodedPath"
      SourceUri = [string]$commits[0].html_url
      ProviderDigest = $null
      ChecksumUris = @()
      SignatureUris = @()
    }
  }

  if ($Operation.DownloadProvider -ne 'GitHubReleaseApi') {
    throw "Unsupported download provider '$($Operation.DownloadProvider)' for $($Operation.PackageId)."
  }
  if (-not [uri]::IsWellFormedUriString([string]$Operation.DownloadUri, [UriKind]::Absolute) -or ([uri]$Operation.DownloadUri).Scheme -ne 'https' -or ([uri]$Operation.DownloadUri).Host -ne 'api.github.com') {
    throw "The GitHub release API URI for $($Operation.PackageId) must use HTTPS on api.github.com."
  }
  $release = Invoke-RestMethod -Uri $Operation.DownloadUri -Headers @{
    Accept = 'application/vnd.github+json'
    'User-Agent' = 'RIDE-Windows'
  } -ErrorAction Stop
  $matches = @($release.assets | Where-Object { $_.name -match $Operation.AssetPattern })
  if ($matches.Count -ne 1) {
    throw "Expected one latest $($Operation.Architecture) installer for $($Operation.PackageId); found $($matches.Count)."
  }
  $asset = $matches[0]
  if (-not $asset.name -or [IO.Path]::GetFileName([string]$asset.name) -ne [string]$asset.name -or $asset.name -match '[\\/]') {
    throw "The release asset filename for $($Operation.PackageId) is invalid."
  }
  $uri = [string]$asset.browser_download_url
  if (-not [uri]::IsWellFormedUriString($uri, [UriKind]::Absolute) -or ([uri]$uri).Scheme -ne 'https') {
    throw "The release asset URL for $($Operation.PackageId) is not a valid HTTPS URL."
  }
  $version = [string]$release.tag_name
  if ($Operation.TagPrefix -and $version.StartsWith([string]$Operation.TagPrefix, [StringComparison]::Ordinal)) { $version = $version.Substring(([string]$Operation.TagPrefix).Length) }
  if ($version.StartsWith('v', [StringComparison]::OrdinalIgnoreCase)) { $version = $version.Substring(1) }
  if (-not $version -or $version -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]*$') { throw "The latest release for $($Operation.PackageId) has an invalid version tag." }

  $publisherChecksum = $null
  if ($Operation.PublisherChecksumSource -eq 'ReleaseNotes') {
    $escapedName = [regex]::Escape([string]$asset.name)
    $checksumMatches = @([regex]::Matches([string]$release.body, "(?im)^\s*\|?\s*${escapedName}\s*\|\s*([0-9a-f]{64})\s*\|?\s*$|^\s*([0-9a-f]{64})\s+${escapedName}\s*$"))
    $checksums = @($checksumMatches | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value.ToLowerInvariant() } else { $_.Groups[2].Value.ToLowerInvariant() } } | Select-Object -Unique)
    if ($checksums.Count -gt 1) { throw "Conflicting publisher checksums for $($asset.name)." }
    if ($checksums.Count -eq 1) { $publisherChecksum = $checksums[0] }
  }
  [pscustomobject]@{
    PackageId = [string]$Operation.PackageId
    OriginUri = [string]$Operation.ProductUri
    Version = $version
    Architecture = [string]$Operation.Architecture
    FileName = [string]$asset.name
    Uri = $uri
    SourceUri = [string]$release.html_url
    ProviderDigest = [string]$asset.digest
    PublisherSha256 = $publisherChecksum
    PublisherChecksumUri = if ($publisherChecksum) { [string]$release.html_url } else { $null }
    ChecksumUris = @($release.assets | Where-Object { $_.name -match '(?i)(checksum|checksums|sha256)' -and $_.name -notmatch '(?i)(\.sig|\.asc|\.gpg)$' } | ForEach-Object { [string]$_.browser_download_url })
    SignatureUris = @($release.assets | Where-Object { $_.name -match '(?i)(\.sig|\.asc|\.gpg)$' } | ForEach-Object { [string]$_.browser_download_url })
  }
}

function Get-RideArtifactFileEvidence {
  param([Parameter(Mandatory)][string] $Path)
  $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
  $certificate = if ($signature) { $signature.SignerCertificate } else { $null }
  $timestampCertificate = if ($signature) { $signature.TimeStamperCertificate } else { $null }
  $file = Get-Item -LiteralPath $Path -ErrorAction Stop
  [pscustomobject]@{
    Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    FileSize = $file.Length
    FileVersion = $file.VersionInfo.FileVersion
    ProductVersion = $file.VersionInfo.ProductVersion
    AuthenticodeStatus = if ($signature) { [string]$signature.Status } else { 'Unavailable' }
    AuthenticodeSigner = if ($certificate) { $certificate.Subject } else { $null }
    AuthenticodeIssuer = if ($certificate) { $certificate.Issuer } else { $null }
    AuthenticodeThumbprint = if ($certificate) { $certificate.Thumbprint } else { $null }
    TimestampSigner = if ($timestampCertificate) { $timestampCertificate.Subject } else { $null }
    TimestampThumbprint = if ($timestampCertificate) { $timestampCertificate.Thumbprint } else { $null }
  }
}

function Add-RideArtifactObservation {
  param(
    [Parameter(Mandatory = $true)][pscustomobject] $Artifact,
    [Parameter(Mandatory = $true)][string] $Path,
    [Parameter(Mandatory = $true)][string] $Sha256,
    [Parameter(Mandatory = $true)][string] $ObservationPath,
    [Parameter(Mandatory = $true)][string] $Route,
    [object[]] $Contents = @()
  )

  $fileEvidence = Get-RideArtifactFileEvidence -Path $Path
  $observation = [ordered]@{
    ObservationId = [guid]::NewGuid().ToString('N')
    RunId = if ($env:RIDE_TEST_RUN_ID -match '^[0-9a-f]{32}$') { $env:RIDE_TEST_RUN_ID } else { $null }
    PackageId = if ($Artifact.ArtifactId) { $null } else { $Artifact.PackageId }
    ArtifactId = $Artifact.ArtifactId
    Version = $Artifact.Version
    Architecture = $Artifact.Architecture
    FileName = $Artifact.FileName
    OriginUri = $Artifact.OriginUri
    SourceUri = $Artifact.Uri
    ReleaseUri = $Artifact.SourceUri
    ObservedAtUtc = [DateTime]::UtcNow.ToString('o')
    Route = $Route
    AcquisitionKind = $Artifact.AcquisitionKind
    Sha256 = $Sha256
    ProviderDigest = $Artifact.ProviderDigest
    PublisherSha256 = $Artifact.PublisherSha256
    PublisherChecksumUri = $Artifact.PublisherChecksumUri
    PublisherChecksumResult = if ($Artifact.PublisherSha256) { 'Matched' } else { 'Unavailable' }
    ChecksumUris = @($Artifact.ChecksumUris)
    SignatureUris = @($Artifact.SignatureUris)
    AuthenticodeStatus = $fileEvidence.AuthenticodeStatus
    AuthenticodeSigner = $fileEvidence.AuthenticodeSigner
    AuthenticodeIssuer = $fileEvidence.AuthenticodeIssuer
    AuthenticodeThumbprint = $fileEvidence.AuthenticodeThumbprint
    TimestampSigner = $fileEvidence.TimestampSigner
    TimestampThumbprint = $fileEvidence.TimestampThumbprint
    FileSize = $fileEvidence.FileSize
    FileVersion = $fileEvidence.FileVersion
    ProductVersion = $fileEvidence.ProductVersion
    Contents = @($Contents)
  }

  # Keep evidence with the retained bytes even when the shared library is unavailable.
  [pscustomobject]$observation | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath ($Path + '.ride.json') -Encoding UTF8 -ErrorAction Stop
  $libraryLock = $null
  $temporaryPath = $null
  try {
    $parent = Split-Path -Parent $ObservationPath
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $libraryLock = [IO.File]::Open($ObservationPath + '.lock', [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $library = if (Test-Path -LiteralPath $ObservationPath -PathType Leaf) {
      Get-Content -LiteralPath $ObservationPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    else { [pscustomobject]@{ SchemaVersion = 1; Observations = @() } }
    if ($library.SchemaVersion -ne 1) { throw "Unsupported artifact observation schema in $ObservationPath." }
    $entries = @($library.Observations) + @([pscustomobject]$observation)
    $json = [pscustomobject]@{ SchemaVersion = 1; Observations = $entries } | ConvertTo-Json -Depth 12
    $temporaryPath = $ObservationPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    Set-Content -LiteralPath $temporaryPath -Value $json -Encoding UTF8
    $destinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ObservationPath)
    $sourcePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($temporaryPath)
    if ([IO.File]::Exists($destinationPath)) { [IO.File]::Replace($sourcePath, $destinationPath, [NullString]::Value) }
    else { [IO.File]::Move($sourcePath, $destinationPath) }
  }
  catch {
    Write-Warning "Downloaded artifact is retained, but the shared observation library could not be updated: $($_.Exception.Message)"
  }
  finally {
    if ($libraryLock) { $libraryLock.Dispose() }
    if ($temporaryPath -and (Test-Path -LiteralPath $temporaryPath)) { Remove-Item -LiteralPath $temporaryPath -Force }
  }
}

function Save-RidePackageArtifact {
  <#
  .SYNOPSIS
    Retain a versioned artifact and record observed integrity metadata.

  .DESCRIPTION
    Creates item/version directories, downloads when absent, computes SHA-256, checks a supplied
    provider digest and supported publisher checksum, and records file/member observations.
    Always retains a sidecar; warns if shared recording fails. Does not invoke an installer
    or authenticate the publisher from a local hash.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER DestinationDirectory
    Destination root; item and resolved-version subdirectories are created. Wildcards are rejected.

  .PARAMETER ObservationPath
    JSON observation library path; defaults to catalog/artifact-observations.json in the repository.

  .PARAMETER Route
    Observation route label; defaults to direct.

  .EXAMPLE
    Get-Help Save-RidePackageArtifact -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. PackageId/ArtifactId, Version, Architecture,
    FileName, Path, Uri, Sha256, and ProviderDigest.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $DestinationDirectory,
    [string] $ObservationPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/artifact-observations.json'),
    [string] $Route = 'direct'
  )

  $artifact = Resolve-RidePackageArtifact -Operation $Operation
  if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($DestinationDirectory)) { throw 'The artifact destination must not contain wildcard characters.' }
  $DestinationDirectory = [IO.Path]::GetFullPath($DestinationDirectory)
  New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
  $itemId = if ($Operation.Kind -eq 'Artifact') { [string]$Operation.ArtifactId } else { [string]$Operation.PackageId }
  $packageDirectory = Join-Path $DestinationDirectory $itemId
  New-Item -ItemType Directory -Path $packageDirectory -Force | Out-Null
  $versionDirectory = Join-Path $packageDirectory $artifact.Version
  New-Item -ItemType Directory -Path $versionDirectory -Force | Out-Null
  $installer = Join-Path $versionDirectory $artifact.FileName

  $acquisitionKind = 'Cache'
  if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    Invoke-WebRequest -Uri $artifact.Uri -OutFile $installer -UseBasicParsing -ErrorAction Stop
    $acquisitionKind = 'Download'
  }
  $artifact | Add-Member -NotePropertyName AcquisitionKind -NotePropertyValue $acquisitionKind -Force
  $sha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($artifact.ProviderDigest) {
    $digestMatch = [regex]::Match([string]$artifact.ProviderDigest, '^sha256:([0-9a-fA-F]{64})$')
    if (-not $digestMatch.Success) { throw "Unrecognized provider digest format for $($Operation.PackageId)." }
    if ($digestMatch.Groups[1].Value.ToLowerInvariant() -ne $sha256) { throw "Provider SHA-256 digest mismatch for $($Operation.PackageId) $($artifact.Version)." }
  }
  if ($artifact.PublisherSha256 -and $artifact.PublisherSha256 -ne $sha256) { throw "Publisher SHA-256 checksum mismatch for $($artifact.FileName)." }
  $contents = @()
  if ($Operation.InstallerType -eq 'SysmonZip') {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($installer)
    $inspectionRoot = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-Artifact-' + [guid]::NewGuid().ToString('N'))
    try {
      $entries = @($archive.Entries | Where-Object FullName -eq 'Sysmon64.exe')
      if ($entries.Count -ne 1) { throw 'Sysmon archive must contain exactly one root Sysmon64.exe.' }
      New-Item -ItemType Directory -Path $inspectionRoot -Force | Out-Null
      $memberPath = Join-Path $inspectionRoot 'Sysmon64.exe'
      [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $memberPath)
      $member = Get-RideArtifactFileEvidence -Path $memberPath
      $member | Add-Member -NotePropertyName ArchivePath -NotePropertyValue 'Sysmon64.exe'
      $member | Add-Member -NotePropertyName ParentSha256 -NotePropertyValue $sha256
      $contents = @($member)
    }
    finally {
      $archive.Dispose()
      if (Test-Path -LiteralPath $inspectionRoot) {
        $resolvedInspection = (Resolve-Path -LiteralPath $inspectionRoot).Path
        if ($resolvedInspection -ne [IO.Path]::GetFullPath($inspectionRoot) -or (Split-Path -Leaf $resolvedInspection) -notmatch '^RIDE-Artifact-[0-9a-f]{32}$') { throw 'Unexpected artifact inspection directory.' }
        Remove-Item -LiteralPath $resolvedInspection -Recurse -Force
      }
    }
  }
  Add-RideArtifactObservation -Artifact $artifact -Path $installer -Sha256 $sha256 -ObservationPath $ObservationPath -Route $Route -Contents $contents
  [pscustomobject]@{
    PackageId = if ($artifact.ArtifactId) { $null } else { $artifact.PackageId }
    ArtifactId = $artifact.ArtifactId
    Version = $artifact.Version
    Architecture = $artifact.Architecture
    FileName = $artifact.FileName
    Path = $installer
    Uri = $artifact.Uri
    Sha256 = $sha256
    ProviderDigest = $artifact.ProviderDigest
  }
}

function Get-RidePackagePrerequisiteDirectory {
  param([hashtable] $Operation)
  if (-not $Operation.PrerequisiteProgramFilesExecutable) { return }
  $relative = [string]$Operation.PrerequisiteProgramFilesExecutable
  if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $relative -match '["\r\n:*?]') { throw 'Invalid package prerequisite executable path.' }
  $executable = Join-Path $env:ProgramFiles $relative
  if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw "$($Operation.Id) requires $($Operation.PrerequisitePackageId) at '$executable'. Install the prerequisite first and remove it last." }
  Split-Path -Parent $executable
}

function Invoke-RidePackageInstallerProcess {
  param([hashtable] $Operation, [string] $FilePath, [string] $ArgumentList)
  $prerequisiteDirectory = Get-RidePackagePrerequisiteDirectory -Operation $Operation
  $originalPath = $env:PATH
  try {
    # Newly installed Git is not yet in this process's inherited PATH.
    if ($prerequisiteDirectory) { $env:PATH = $prerequisiteDirectory + ';' + $originalPath }
    Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WindowStyle Hidden -Wait -PassThru
  }
  finally { $env:PATH = $originalPath }
}

function Install-RidePackage {
  <#
  .SYNOPSIS
    Install the catalog package from a retained upstream artifact.

  .DESCRIPTION
    Downloads via Save-RidePackageArtifact, runs an EXE/MSI installer or stages Sysmon64 from the
    Microsoft archive, then verifies presence. Retains artifacts on failure and cleans Sysmon
    staging. Use the engine for privilege, preview, and snapshot capture.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER CacheDirectory
    Versioned artifact cache root selected by the engine for the operation scope.

  .EXAMPLE
    Get-Help Install-RidePackage -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $CacheDirectory
  )

  $null = Get-RidePackagePrerequisiteDirectory -Operation $Operation
  $download = Save-RidePackageArtifact -Operation $Operation -DestinationDirectory $CacheDirectory
  if ($Operation.InstallerType -eq 'SysmonZip') {
    $staging = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-Sysmon-' + [guid]::NewGuid().ToString('N'))
    $installDirectory = Join-Path (Get-RideSysmonInstallRoot) $download.Version
    try {
      New-Item -ItemType Directory -Path $staging -Force | Out-Null
      Expand-Archive -LiteralPath $download.Path -DestinationPath $staging -Force
      $sourceExe = Join-Path $staging 'Sysmon64.exe'
      if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) { throw 'The Microsoft Sysmon archive did not contain Sysmon64.exe.' }
      New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
      $installedExe = Join-Path $installDirectory 'Sysmon64.exe'
      Copy-Item -LiteralPath $sourceExe -Destination $installedExe -Force
      $process = Start-Process -FilePath $installedExe -ArgumentList '-accepteula -i' -Wait -PassThru
      if ($process.ExitCode -ne 0) { throw "Sysmon installer exited with code $($process.ExitCode). Archive retained at '$($download.Path)' and executable at '$installedExe'." }
      if (-not (Get-RideInstalledPackage -Operation $Operation).Present) { throw "Sysmon installer completed but its service was not detected. Archive retained at '$($download.Path)'." }
    }
    finally {
      if (Test-Path -LiteralPath $staging) {
        $resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
        if ($resolvedStaging -ne [IO.Path]::GetFullPath($staging) -or (Split-Path -Leaf $resolvedStaging) -notmatch '^RIDE-Sysmon-[0-9a-f]{32}$') { throw 'Unexpected Sysmon staging directory.' }
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
      }
    }
    return
  }
  if ($Operation.InstallerType -notin @('Exe', 'Msi')) { throw "Unsupported installer type for $($Operation.Id): $($Operation.InstallerType)" }
  $installerExe = $download.Path
  $installerArguments = $Operation.InstallerArguments
  if ($Operation.InstallerType -eq 'Msi') {
    $installerExe = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $installerArguments = '/i "' + $download.Path + '" ' + $Operation.InstallerArguments
  }
  $process = Invoke-RidePackageInstallerProcess -Operation $Operation -FilePath $installerExe -ArgumentList $installerArguments
  $successExitCodes = if ($Operation.SuccessExitCodes) { @($Operation.SuccessExitCodes) } else { @(0) }
  if ($process.ExitCode -notin $successExitCodes) { throw "Installer for $($Operation.Name) exited with code $($process.ExitCode). Artifact retained at '$($download.Path)'." }
  if ($process.ExitCode -eq 3010) { Write-Warning "$($Operation.Name) installation succeeded; a restart is required." }
  if (-not (Get-RideInstalledPackage -Operation $Operation).Present) { throw "Installer completed but $($Operation.Name) was not detected afterward. Artifact retained at '$($download.Path)'." }
}

function Uninstall-RidePackage {
  <#
  .SYNOPSIS
    Run the detected package uninstall command and verify absence.

  .DESCRIPTION
    Returns when absent. Parses registered quiet/uninstall strings and applies declared fallback
    arguments when needed. Throws on a nonzero exit or remaining package presence. Use the engine;
    no exact-version backup is created here.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Uninstall-RidePackage -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $installed = Get-RideInstalledPackage -Operation $Operation
  if (-not $installed.Present) { return }
  $command = if ($installed.QuietUninstallString) { $installed.QuietUninstallString } else { $installed.UninstallString }
  if (-not $command) { throw "No uninstall command was registered for $($installed.DisplayName)." }

  $exe = $null
  $arguments = ''
  if ($command -match '^\s*"([^"]+)"\s*(.*)$') {
    $exe = $matches[1]
    $arguments = $matches[2]
  }
  elseif ($command -match '^\s*(\S+\.exe)\s*(.*)$') {
    $exe = $matches[1]
    $arguments = $matches[2]
  }
  if (-not $exe) { throw "Could not parse the uninstall command for $($installed.DisplayName)." }
  if ($Operation.InstallerType -eq 'Msi') {
    if ([IO.Path]::GetFileName($exe) -notmatch '^(?i)msiexec(?:\.exe)?$') { throw 'MSI removal requires a registered msiexec uninstall command.' }
    $arguments = [regex]::Replace($arguments, '(?i)(^|\s)/I(?=\s|\{)', '$1/X')
  }
  if ($arguments -notmatch '(?i)(/quiet|/qn|/s|/silent|/verysilent|--uninstall)(?=\s|$)') { $arguments = ($arguments + ' ' + $Operation.UninstallerArguments).Trim() }
  $process = Invoke-RidePackageInstallerProcess -Operation $Operation -FilePath $exe -ArgumentList $arguments
  $successExitCodes = if ($Operation.SuccessExitCodes) { @($Operation.SuccessExitCodes) } else { @(0) }
  if ($process.ExitCode -notin $successExitCodes) { throw "Uninstaller for $($Operation.Name) exited with code $($process.ExitCode)." }
  if ($process.ExitCode -eq 3010) { Write-Warning "$($Operation.Name) removal succeeded; a restart is required." }
  if ((Get-RideInstalledPackage -Operation $Operation).Present) { throw "Uninstaller completed but $($Operation.Name) is still detected." }
}

Export-ModuleMember -Function Get-RideInstalledPackage, Resolve-RidePackageArtifact, Save-RidePackageArtifact, Install-RidePackage, Uninstall-RidePackage
