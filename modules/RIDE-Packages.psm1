<#
.SYNOPSIS
  Inspect package presence, retain upstream artifacts, and run catalog installers.

.DESCRIPTION
  Queries uninstall entries or the Sysmon service. Resolves explicit HTTPS installers,
  GitHub release/file revisions or the Microsoft Sysmon archive; downloads versioned artifacts, checks available provider digests, and
  records SHA-256/Authenticode observations. Install/uninstall run declared commands and check
  presence; hashes alone are not publisher authentication. Downloads retain public license
  references and GitHub release assets must belong to the declared publisher repository.

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
  Version: 0.9.0
  Changelog:
    - 0.9.0: Reject conflicting scope, language, architecture and destinations for reviewed user packages.
    0.8.0: Route checksummed WinSCP portable page acquisition.
    0.7.0: Resolve Signal feeds, check SHA-512 and preserve declared user data on removal.
    0.6.1: Allow a declared EXE uninstaller for MSI wrapper distributions.
    0.6.0: Add official publisher adapters, portable ownership and acquisition selection evidence.
    0.5.0: Inspect and extract declared self-contained ZIP installers with member hashes.
    0.4.0: Resolve explicit versioned HTTPS EXE/MSI installers with optional expected SHA-256.
    0.3.0: Record publisher license references and constrain GitHub assets to the declared project.
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


$script:ModuleVersion = '0.8.0'
Import-Module (Join-Path $PSScriptRoot 'RIDE.InstallerInspection.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PublisherSources.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PackageSelection.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE-PortablePackages.psm1') -ErrorAction Stop

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

  $Operation = Resolve-RidePackageSelection -Operation $Operation
  if ($Operation.InstallerType -eq 'Portable') { return Get-RidePortableState -Operation $Operation }
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

  if ($Operation.ConflictingDisplayNamePattern) {
    $allRoots=@('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($root in $allRoots) {
      foreach ($entry in (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
        if ($entry.DisplayName -match $Operation.ConflictingDisplayNamePattern -and
            ($root -notlike 'HKCU:*' -or $entry.DisplayName -notmatch $Operation.DisplayNamePattern -or [string]$entry.InstallLocation -ine [string]$Operation.InstallDirectory)) {
          throw "Conflicting existing edition or destination for '$($Operation.Id)': $($entry.DisplayName). Review it before migration."
        }
      }
    }
  }
  $uninstallRoots = if ($Operation.Scope -eq 'User') { @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') } else { @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  ) }
  foreach ($root in $uninstallRoots) {
    foreach ($entry in (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
      if ($entry.DisplayName -match $Operation.DisplayNamePattern) {
        if ($Operation.MozillaChannel) {
          $channelPath=Join-Path $entry.InstallLocation 'defaults/pref/channel-prefs.js'
          if (-not (Test-Path -LiteralPath $channelPath -PathType Leaf) -or (Get-Content -LiteralPath $channelPath -Raw) -notmatch ('pref\("app.update.channel",\s*"'+[regex]::Escape($Operation.MozillaChannel)+'"\)')) { throw "Conflicting or unverifiable Mozilla update channel for '$($Operation.Id)'; review the existing edition." }
        }
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
    Resolves an explicit versioned HTTPS installer, or queries an allowed GitHub release API,
    immutable GitHub file commit or Microsoft Sysmon page.
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

  if ($Operation.DownloadProvider -in @('VSCodeUpdateApi', 'MozillaVersionsJson', 'PublisherLinkPage', 'SignalDesktopFeed', 'WinSCPPortablePage')) { return Resolve-RidePublisherArtifact -Operation $Operation }
  if ($Operation.DownloadProvider -eq 'DirectHttps') {
    if (-not [uri]::IsWellFormedUriString([string]$Operation.DownloadUri, [UriKind]::Absolute)) { throw 'A direct installer requires an absolute HTTPS URL.' }
    $source = [uri]$Operation.DownloadUri
    if ($source.Scheme -ne 'https' -or -not $source.IsDefaultPort -or $source.UserInfo -or $source.Fragment) { throw 'A direct installer requires HTTPS on the default port without credentials or fragments.' }
    $assetExtension = if ($Operation.PortableFormat -eq 'File') { [IO.Path]::GetExtension([string]$Operation.AssetName) } elseif ($Operation.ArchiveType -eq 'Zip' -or $Operation.PortableFormat -eq 'Zip') { '.zip' } else { '.' + ([string]$Operation.InstallerType).ToLowerInvariant() }
    if ($Operation.ArchiveType -and $Operation.ArchiveType -notin @('None', 'Zip')) { throw 'Unsupported ArchiveType.' }
    if ($Operation.ArchiveType -eq 'Zip' -and $Operation.InstallerType -ne 'Portable') {
      $entry = [string]$Operation.InstallerEntry
      if (-not $entry -or $entry.Length -gt 240 -or $entry -match '[\\\x00-\x1f:"*?<>|]|^/|(^|/)\.{1,2}(/|$)|[. ](/|$)|//|/$' -or
          [IO.Path]::GetExtension($entry) -ne ('.' + ([string]$Operation.InstallerType).ToLowerInvariant())) { throw 'ZIP requires a safe matching EXE/MSI InstallerEntry.' }
      if ($Operation.ContainsKey('ExpectedInstallerSha256') -and $Operation.ExpectedInstallerSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'ExpectedInstallerSha256 must contain 64 hexadecimal characters.' }
    } elseif ($Operation.ContainsKey('InstallerEntry') -or $Operation.ContainsKey('ExpectedInstallerSha256')) { throw 'InstallerEntry and ExpectedInstallerSha256 require ArchiveType Zip.' }
    if ($Operation.PackageVersion -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]*$' -or
        $Operation.InstallerType -notin @('Exe', 'Msi', 'Portable') -or
        $Operation.AssetName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]*\.(exe|msi|zip)$' -or
        [IO.Path]::GetExtension([string]$Operation.AssetName) -ne $assetExtension) { throw 'A direct installer requires a safe version and an EXE/MSI or ZIP filename matching its metadata.' }
    if ($Operation.ContainsKey('ExpectedSha256') -and $Operation.ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'ExpectedSha256 must contain 64 hexadecimal characters.' }
    return [pscustomobject]@{
      PackageId = [string]$Operation.PackageId
      OriginUri = if ($Operation.ProductUri) { [string]$Operation.ProductUri } else { $source.GetLeftPart([UriPartial]::Authority) }
      Version = [string]$Operation.PackageVersion
      Architecture = [string]$Operation.Architecture
      FileName = [string]$Operation.AssetName
      Uri = [string]$Operation.DownloadUri
      SourceUri = [string]$Operation.DownloadUri
      ProviderDigest = if ($Operation.ExpectedSha256) { 'sha256:' + $Operation.ExpectedSha256 } else { $null }
      ChecksumUris = @(); SignatureUris = @()
    }
  }

  if ($Operation.DownloadProvider -eq 'SysinternalsSysmonPage') {
    if (-not [uri]::IsWellFormedUriString([string]$Operation.VersionUri, [UriKind]::Absolute) -or ([uri]$Operation.VersionUri).Scheme -ne 'https' -or ([uri]$Operation.VersionUri).Host -ne 'learn.microsoft.com') { throw 'Sysmon version discovery must use its Microsoft Learn HTTPS page.' }
    if (-not [uri]::IsWellFormedUriString([string]$Operation.DownloadUri, [UriKind]::Absolute) -or ([uri]$Operation.DownloadUri).Scheme -ne 'https' -or ([uri]$Operation.DownloadUri).Host -ne 'download.sysinternals.com') { throw 'Sysmon downloads must use Microsoft Sysinternals HTTPS hosting.' }
    $page = Invoke-WebRequest -Uri $Operation.VersionUri -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
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
    $commits = @(Invoke-RestMethod -Uri $Operation.DownloadUri -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'RIDE-Windows' } -TimeoutSec 120 -ErrorAction Stop)
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
  $release = Invoke-RestMethod -Uri $Operation.DownloadUri -TimeoutSec 120 -Headers @{
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
  $repositoryMatch = [regex]::Match(([uri]$Operation.DownloadUri).AbsolutePath, '^/repos/(?<repository>[^/]+/[^/]+)/releases/latest$')
  if (-not $repositoryMatch.Success) { throw 'GitHub release discovery must identify the declared publisher repository.' }
  $assetUri = [uri]$uri
  $publisherPrefix = '/' + $repositoryMatch.Groups['repository'].Value + '/releases/download/'
  if ($assetUri.Host -ne 'github.com' -or -not $assetUri.IsDefaultPort -or $assetUri.UserInfo -or -not $assetUri.AbsolutePath.StartsWith($publisherPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The release asset for $($Operation.PackageId) must come from the declared publisher repository."
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
    OriginUri = if ($Operation.ProductUri) { [string]$Operation.ProductUri } else { 'https://github.com/' + $repositoryMatch.Groups['repository'].Value }
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
    Variant = $Artifact.SelectedVariant
    Provider = $Artifact.DownloadProvider
    License = $Artifact.License
    LicenseUri = $Artifact.LicenseUri
    TermsUri = $Artifact.TermsUri
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
    or authenticate the publisher from a local hash. Copies publisher license references
    into the result and evidence; does not read private user/company license reviews.

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

  $Operation = Resolve-RidePackageSelection -Operation $Operation
  $artifact = Resolve-RidePackageArtifact -Operation $Operation
  # Keep Windows PowerShell 5.1 payload transfers from rendering byte progress.
  $ProgressPreference = 'SilentlyContinue'
  # Public references accompany the exact retained version; private review decisions stay local.
  foreach ($field in @('License', 'LicenseUri', 'TermsUri')) {
    $artifact | Add-Member -NotePropertyName $field -NotePropertyValue $Operation[$field] -Force
  }
  $artifact | Add-Member -NotePropertyName SelectedVariant -NotePropertyValue $Operation.SelectedVariant -Force
  $artifact | Add-Member -NotePropertyName DownloadProvider -NotePropertyValue $Operation.DownloadProvider -Force
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
    $temporaryDownload = $installer + '.download-' + [guid]::NewGuid().ToString('N')
    $downloadParameters = @{ Uri = $artifact.Uri; OutFile = $temporaryDownload; UseBasicParsing = $true; TimeoutSec = 1800; ErrorAction = 'Stop' }
    if ($Operation.DownloadProvider -eq 'DirectHttps') {
      $downloadParameters.Headers = @{ Referer = ([uri]$artifact.Uri).GetLeftPart([UriPartial]::Authority) + '/' }
      $downloadParameters.UserAgent = 'Mozilla/5.0 RIDE-PackageDownload/0.5'
    }
    try {
      Invoke-WebRequest @downloadParameters
      if (-not (Test-Path -LiteralPath $temporaryDownload -PathType Leaf) -or (Get-Item -LiteralPath $temporaryDownload).Length -eq 0) { throw 'Publisher returned an empty artifact.' }
      Move-Item -LiteralPath $temporaryDownload -Destination $installer -ErrorAction Stop
    } finally {
      if (Test-Path -LiteralPath $temporaryDownload -PathType Leaf) { Remove-Item -LiteralPath $temporaryDownload -Force }
    }
    $acquisitionKind = 'Download'
  }
  $artifact | Add-Member -NotePropertyName AcquisitionKind -NotePropertyValue $acquisitionKind -Force
  $sha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($artifact.ProviderDigest) {
    $digestMatch = [regex]::Match([string]$artifact.ProviderDigest, '^(sha256|sha512):([0-9a-fA-F]+)$')
    if (-not $digestMatch.Success) { throw "Unrecognized provider digest format for $($Operation.PackageId)." }
    $algorithm = $digestMatch.Groups[1].Value.ToUpperInvariant()
    $expectedLength = if ($algorithm -eq 'SHA256') { 64 } else { 128 }
    if ($digestMatch.Groups[2].Value.Length -ne $expectedLength) { throw "Unrecognized provider digest length for $($Operation.PackageId)." }
    $actual = if ($algorithm -eq 'SHA256') { $sha256 } else { (Get-FileHash -LiteralPath $installer -Algorithm SHA512 -ErrorAction Stop).Hash.ToLowerInvariant() }
    if ($digestMatch.Groups[2].Value.ToLowerInvariant() -ne $actual) { throw "Provider $($algorithm.Replace('SHA','SHA-')) digest mismatch for $($Operation.PackageId) $($artifact.Version)." }
  }
  if ($artifact.PublisherSha256 -and $artifact.PublisherSha256 -ne $sha256) { throw "Publisher SHA-256 checksum mismatch for $($artifact.FileName)." }
  $contents = @()
  if ($Operation.ArchiveType -eq 'Zip' -and $Operation.InstallerType -ne 'Portable') {
    $inspection = Get-RideInstallerInspection -Path $installer -InstallerEntry $Operation.InstallerEntry -Confirm:$false
    if ($inspection.InstallerType -ne $Operation.InstallerType) { throw 'ZIP installer content does not match InstallerType.' }
    if ($Operation.ExpectedInstallerSha256 -and $inspection.InstallerSha256 -ne $Operation.ExpectedInstallerSha256) { throw 'ZIP installer SHA-256 digest mismatch.' }
    $contents = @([pscustomobject]@{ ArchivePath = $Operation.InstallerEntry; Sha256 = $inspection.InstallerSha256; ParentSha256 = $sha256 })
  }
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
  $fileEvidence = Get-RideArtifactFileEvidence -Path $installer
  if ($fileEvidence.AuthenticodeStatus -eq 'HashMismatch' -or @($contents | Where-Object AuthenticodeStatus -eq 'HashMismatch').Count) { throw 'Artifact signature integrity failure.' }
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
    SelectedVariant = $artifact.SelectedVariant
    DownloadProvider = $artifact.DownloadProvider
    SourceUri = $artifact.SourceUri
    OriginUri = $artifact.OriginUri
    ChecksumUris = @($artifact.ChecksumUris)
    SignatureUris = @($artifact.SignatureUris)
    FileEvidence = $fileEvidence
    License = $artifact.License
    LicenseUri = $artifact.LicenseUri
    TermsUri = $artifact.TermsUri
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

function Test-RidePackageAdministrator {
  ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-RidePackageExecutionContext {
  param([hashtable] $Operation)
  if ($Operation.RequiresUnelevatedUser -and (Test-RidePackageAdministrator)) { throw 'This current-user installer requires a non-elevated PowerShell session.' }
}

function Invoke-RidePackageInstallerProcess {
  param([hashtable] $Operation, [string] $FilePath, [string] $ArgumentList)
  Assert-RidePackageExecutionContext -Operation $Operation
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
    Downloads via Save-RidePackageArtifact, runs a direct or ZIP-contained EXE/MSI installer or stages Sysmon64 from the
    Microsoft archive, then verifies presence. Retains artifacts on failure and cleans installer
    staging. ZIP supports one self-contained installer. Use the engine for privilege, preview,
    and snapshot capture.

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
    System.Management.Automation.PSCustomObject. Retained artifact evidence after successful installation.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $CacheDirectory
  )

  $Operation = Resolve-RidePackageSelection -Operation $Operation
  $null = Get-RidePackagePrerequisiteDirectory -Operation $Operation
  Assert-RidePackageExecutionContext -Operation $Operation
  if ($Operation.LocalAppDataInstallDirectory) {
    $expectedRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs'
    if (-not $Operation.InstallDirectory.StartsWith(($expectedRoot+'\'),[StringComparison]::OrdinalIgnoreCase)) { throw 'Current-user installation destination is outside the current user Programs directory.' }
    foreach ($directory in @($expectedRoot,$Operation.InstallDirectory)) {
      if ((Test-Path -LiteralPath $directory) -and ((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Current-user installation destination cannot use reparse points.' }
    }
    if ((Test-Path -LiteralPath $Operation.InstallDirectory) -and -not (Get-RideInstalledPackage -Operation $Operation).Present) { throw 'Unowned content occupies the current-user installation destination; review it before installing.' }
  }
  $download = Save-RidePackageArtifact -Operation $Operation -DestinationDirectory $CacheDirectory
  if ($download.Sha256 -and (Get-FileHash -LiteralPath $download.Path -Algorithm SHA256).Hash -ne $download.Sha256) { throw 'Retained artifact SHA-256 changed before installation.' }
  if ($Operation.InstallerType -eq 'Portable') { Install-RidePortablePayload -Operation $Operation -Artifact $download; return $download }
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
  if ($Operation.InstallerType -notin @('Exe', 'Msi', 'Portable')) { throw "Unsupported installer type for $($Operation.Id): $($Operation.InstallerType)" }
  $installerPath = $download.Path; $installerStaging = $null
  try {
    if ($Operation.ArchiveType -eq 'Zip' -and $Operation.InstallerType -ne 'Portable') {
      $installerStaging = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-Installer-' + [guid]::NewGuid().ToString('N'))
      $installerStaging = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($installerStaging)
      $null = [IO.Directory]::CreateDirectory($installerStaging)
      $installerPath = Join-Path $installerStaging ([IO.Path]::GetFileName([string]$Operation.InstallerEntry))
      Expand-RideInstallerEntry -Path $download.Path -Entry $Operation.InstallerEntry -Destination $installerPath -Confirm:$false
      $inspection = Get-RideInstallerInspection -Path $installerPath -Confirm:$false
      if ($inspection.InstallerType -ne $Operation.InstallerType) { throw 'ZIP installer content does not match InstallerType.' }
      if ($Operation.ExpectedInstallerSha256 -and $inspection.InstallerSha256 -ne $Operation.ExpectedInstallerSha256) { throw 'ZIP installer SHA-256 digest mismatch.' }
    }
    $installerExe = $installerPath
    $installerArguments = $Operation.InstallerArguments
    if ($Operation.InstallerType -eq 'Msi') {
      $installerExe = Join-Path $env:SystemRoot 'System32\msiexec.exe'
      $installerArguments = '/i "' + $installerPath + '" ' + $Operation.InstallerArguments
    }
    $process = Invoke-RidePackageInstallerProcess -Operation $Operation -FilePath $installerExe -ArgumentList $installerArguments
    $successExitCodes = if ($Operation.SuccessExitCodes) { @($Operation.SuccessExitCodes) } else { @(0) }
    if ($process.ExitCode -notin $successExitCodes) { throw "Installer for $($Operation.Name) exited with code $($process.ExitCode). Artifact retained at '$($download.Path)'." }
    if ($process.ExitCode -eq 3010) { Write-Warning "$($Operation.Name) installation succeeded; a restart is required." }
    if (-not (Get-RideInstalledPackage -Operation $Operation).Present) { throw "Installer completed but $($Operation.Name) was not detected afterward. Artifact retained at '$($download.Path)'." }
  } finally {
    if ($installerStaging -and [IO.Directory]::Exists($installerStaging)) {
      $resolvedStaging = (Get-Item -LiteralPath $installerStaging).FullName
      if ($resolvedStaging -ne [IO.Path]::GetFullPath($installerStaging) -or (Split-Path -Leaf $resolvedStaging) -notmatch '^RIDE-Installer-[0-9a-f]{32}$') { throw 'Unexpected installer staging directory.' }
      Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
  }
  $download
}

function Get-RideRoamingApplicationDataRoot {
  [Environment]::GetFolderPath('ApplicationData')
}

function Invoke-RidePreservingPackageRemoval {
  param([hashtable] $Operation, [string] $FilePath, [string] $ArgumentList)
  if (-not $Operation.PreserveRoamingDirectory) { return Invoke-RidePackageInstallerProcess -Operation $Operation -FilePath $FilePath -ArgumentList $ArgumentList }
  $name=[string]$Operation.PreserveRoamingDirectory
  if ($Operation.Scope -ne 'User' -or $Operation.InstallerType -ne 'Exe' -or $name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,79}$' -or $name.EndsWith('.') -or $name.EndsWith(' ') -or $name -match '^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)' -or $Operation.PreservationProcessName -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Invalid user-data preservation directory.' }
  if ($Operation.PreservationProcessName -and (Get-Process -Name $Operation.PreservationProcessName -ErrorAction SilentlyContinue)) { throw "Close $($Operation.Name) before removing it; user data was not moved." }
  $root=Get-RideRoamingApplicationDataRoot
  if (-not $root -or -not [IO.Path]::IsPathRooted($root)) { throw 'User roaming application-data root is unavailable.' }
  $pending=@(Get-ChildItem -LiteralPath $root -Force -Filter ('.'+$name+'.ride-preserved-*') -ErrorAction Stop)
  if ($pending.Count) { throw "Unfinished user-data preservation requires review at '$($pending[0].FullName)'; no uninstaller was run." }
  $original=Join-Path $root $name
  $holding=Join-Path $root ('.'+$name+'.ride-preserved-'+[guid]::NewGuid().ToString('N'))
  $journal=$holding+'.json'
  $moved=$false
  $directory=$null
  if (Test-Path -LiteralPath $original) {
    $directory=Get-Item -LiteralPath $original -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Refusing a non-directory or reparse-point application-data source.' }
  }
  try {
    if ($directory) {
      [IO.File]::WriteAllText($journal,(@{PackageId=$Operation.PackageId;OriginalPath=$original;PreservedPath=$holding;CreatedAtUtc=[datetime]::UtcNow.ToString('o')} | ConvertTo-Json))
      # Rename within the same parent: preserve bytes, ACLs and unowned contents.
      Move-Item -LiteralPath $original -Destination $holding -ErrorAction Stop
      $moved=$true
    }
    Invoke-RidePackageInstallerProcess -Operation $Operation -FilePath $FilePath -ArgumentList $ArgumentList
  }
  finally {
    if ($moved) {
      if (Test-Path -LiteralPath $original) { throw "User-data restoration has a collision. Preserved data remains at '$holding'; original destination is '$original'." }
      try { Move-Item -LiteralPath $holding -Destination $original -ErrorAction Stop }
      catch { throw "User-data restoration failed. Preserved data remains at '$holding'; original destination is '$original'. $($_.Exception.Message)" }
    }
    if (Test-Path -LiteralPath $journal) { Remove-Item -LiteralPath $journal -ErrorAction Stop }
  }
}

function Uninstall-RidePackage {
  <#
  .SYNOPSIS
    Run the detected package uninstall command and verify absence.

  .DESCRIPTION
    Returns when absent. Parses registered quiet/uninstall strings and applies declared fallback
    arguments when needed. UninstallerType may override the installer format for MSI wrappers.
    A declared user-data preservation contract refuses a running application and temporarily
    renames its Roaming data directory, restoring it after the uninstaller finishes or fails.
    Interrupted restoration retains the directory and journal for review instead of overwriting.
    Throws on a nonzero exit or remaining package presence. Use the engine;
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

  $Operation = Resolve-RidePackageSelection -Operation $Operation
  if ($Operation.InstallerType -eq 'Portable') { Uninstall-RidePortablePayload -Operation $Operation; return }
  Assert-RidePackageExecutionContext -Operation $Operation
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
  $uninstallerType = if ($Operation.UninstallerType) { $Operation.UninstallerType } else { $Operation.InstallerType }
  if ($uninstallerType -eq 'Msi') {
    if ([IO.Path]::GetFileName($exe) -notmatch '^(?i)msiexec(?:\.exe)?$') { throw 'MSI removal requires a registered msiexec uninstall command.' }
    $arguments = [regex]::Replace($arguments, '(?i)(^|\s)/I(?=\s|\{)', '$1/X')
  }
  if ($arguments -notmatch '(?i)(/quiet|/qn|/s|/silent|/verysilent|--uninstall)(?=\s|$)') { $arguments = ($arguments + ' ' + $Operation.UninstallerArguments).Trim() }
  $process = Invoke-RidePreservingPackageRemoval -Operation $Operation -FilePath $exe -ArgumentList $arguments
  $successExitCodes = if ($Operation.SuccessExitCodes) { @($Operation.SuccessExitCodes) } else { @(0) }
  if ($process.ExitCode -notin $successExitCodes) { throw "Uninstaller for $($Operation.Name) exited with code $($process.ExitCode)." }
  if ($process.ExitCode -eq 3010) { Write-Warning "$($Operation.Name) removal succeeded; a restart is required." }
  if ((Get-RideInstalledPackage -Operation $Operation).Present) { throw "Uninstaller completed but $($Operation.Name) is still detected." }
}

Export-ModuleMember -Function Get-RideInstalledPackage, Resolve-RidePackageArtifact, Save-RidePackageArtifact, Install-RidePackage, Uninstall-RidePackage
