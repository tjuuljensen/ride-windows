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
  Version: 0.1.0
  Changelog:
    0.1.0: Establish documented module ownership, version, and exported-command help during this
    walkthrough.
  Supported targets are declared per operation in catalog/operations.psd1. This walkthrough
  validates syntax/help, not Windows state transitions.

.LINK
  docs/models/script-repository-model.md

.LINK
  docs/OPERATIONS.md

#>


$script:ModuleVersion = '0.1.0'

function Get-RideInstalledPackage {
  <#
  .SYNOPSIS
    Inspect declared package presence and uninstall metadata.

  .DESCRIPTION
    Queries machine uninstall entries using DisplayNamePattern, or the Sysmon service for SysmonZip.
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

  $uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
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
  if ($version.StartsWith('v', [StringComparison]::OrdinalIgnoreCase)) { $version = $version.Substring(1) }
  if (-not $version -or $version -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]*$') { throw "The latest release for $($Operation.PackageId) has an invalid version tag." }

  [pscustomobject]@{
    PackageId = [string]$Operation.PackageId
    OriginUri = [string]$Operation.ProductUri
    Version = $version
    Architecture = [string]$Operation.Architecture
    FileName = [string]$asset.name
    Uri = $uri
    SourceUri = [string]$release.html_url
    ProviderDigest = [string]$asset.digest
    ChecksumUris = @($release.assets | Where-Object { $_.name -match '(?i)(checksum|checksums|sha256)' -and $_.name -notmatch '(?i)(\.sig|\.asc|\.gpg)$' } | ForEach-Object { [string]$_.browser_download_url })
    SignatureUris = @($release.assets | Where-Object { $_.name -match '(?i)(\.sig|\.asc|\.gpg)$' } | ForEach-Object { [string]$_.browser_download_url })
  }
}

function Add-RideArtifactObservation {
  param(
    [Parameter(Mandatory = $true)][pscustomobject] $Artifact,
    [Parameter(Mandatory = $true)][string] $Path,
    [Parameter(Mandatory = $true)][string] $Sha256,
    [Parameter(Mandatory = $true)][string] $ObservationPath,
    [Parameter(Mandatory = $true)][string] $Route
  )

  $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
  $observation = [ordered]@{
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
    Sha256 = $Sha256
    ProviderDigest = $Artifact.ProviderDigest
    ChecksumUris = @($Artifact.ChecksumUris)
    SignatureUris = @($Artifact.SignatureUris)
    AuthenticodeStatus = if ($signature) { [string]$signature.Status } else { 'Unavailable' }
    AuthenticodeSigner = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    FileSize = (Get-Item -LiteralPath $Path).Length
  }

  try {
    $parent = Split-Path -Parent $ObservationPath
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $library = if (Test-Path -LiteralPath $ObservationPath -PathType Leaf) {
      Get-Content -LiteralPath $ObservationPath -Raw | ConvertFrom-Json
    }
    else { [pscustomobject]@{ SchemaVersion = 1; Observations = @() } }
    if ($library.SchemaVersion -ne 1) { throw "Unsupported artifact observation schema in $ObservationPath." }
    $entries = @($library.Observations) + @([pscustomobject]$observation)
    $json = [pscustomobject]@{ SchemaVersion = 1; Observations = $entries } | ConvertTo-Json -Depth 8
    $temporaryPath = $ObservationPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    Set-Content -LiteralPath $temporaryPath -Value $json -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination $ObservationPath -Force
  }
  catch {
    Write-Warning "Downloaded artifact is retained, but the shared observation library could not be updated: $($_.Exception.Message)"
    $sidecarPath = $Path + '.ride.json'
    [pscustomobject]$observation | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $sidecarPath -Encoding UTF8
  }
}

function Save-RidePackageArtifact {
  <#
  .SYNOPSIS
    Retain a versioned artifact and record observed integrity metadata.

  .DESCRIPTION
    Creates item/version directories, downloads when absent, computes SHA-256, checks a supplied
    provider digest, and records observations. Falls back to a sidecar when the shared library
    cannot be written. Does not invoke an installer or authenticate the publisher from a local hash.

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

  if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    Invoke-WebRequest -Uri $artifact.Uri -OutFile $installer -UseBasicParsing -ErrorAction Stop
  }
  $sha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($artifact.ProviderDigest) {
    $digestMatch = [regex]::Match([string]$artifact.ProviderDigest, '^sha256:([0-9a-fA-F]{64})$')
    if (-not $digestMatch.Success) { throw "Unrecognized provider digest format for $($Operation.PackageId)." }
    if ($digestMatch.Groups[1].Value.ToLowerInvariant() -ne $sha256) { throw "Provider SHA-256 digest mismatch for $($Operation.PackageId) $($artifact.Version)." }
  }
  Add-RideArtifactObservation -Artifact $artifact -Path $installer -Sha256 $sha256 -ObservationPath $ObservationPath -Route $Route
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

function Install-RidePackage {
  <#
  .SYNOPSIS
    Install the catalog package from a retained upstream artifact.

  .DESCRIPTION
    Downloads via Save-RidePackageArtifact, runs an EXE installer or stages Sysmon64 from the
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
      if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    }
    return
  }
  if ($Operation.InstallerType -ne 'Exe') { throw "Unsupported installer type for $($Operation.Id): $($Operation.InstallerType)" }
  $process = Start-Process -FilePath $download.Path -ArgumentList $Operation.InstallerArguments -Wait -PassThru
  if ($process.ExitCode -ne 0) { throw "Installer for $($Operation.Name) exited with code $($process.ExitCode). Artifact retained at '$($download.Path)'." }
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
  if ($arguments -notmatch '(?i)(/quiet|/s|/silent|--uninstall)') { $arguments = ($arguments + ' ' + $Operation.UninstallerArguments).Trim() }
  $process = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru
  if ($process.ExitCode -ne 0) { throw "Uninstaller for $($Operation.Name) exited with code $($process.ExitCode)." }
  if ((Get-RideInstalledPackage -Operation $Operation).Present) { throw "Uninstaller completed but $($Operation.Name) is still detected." }
}

Export-ModuleMember -Function Get-RideInstalledPackage, Resolve-RidePackageArtifact, Save-RidePackageArtifact, Install-RidePackage, Uninstall-RidePackage
