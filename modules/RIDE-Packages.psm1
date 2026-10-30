<#
.SYNOPSIS
  Inspect package presence, retain upstream artifacts, and run catalog installers.

.DESCRIPTION
  Queries scope-matched uninstall entries, declared current-user Windows Installer products,
  or the Sysmon service. Resolves explicit HTTPS installers, GitHub release/file revisions or
  the Microsoft Sysmon archive; downloads versioned artifacts, checks available provider digests,
  and records SHA-256/Authenticode observations. Install/uninstall run declared commands and check
  presence; declared user-data preservation can wrap selected installers and all removals. Hashes
  alone are not publisher authentication. Downloads retain public license
  references and GitHub release assets must belong to the declared publisher repository.
  Latest-release metadata is reused for at most five minutes within this process.
  Shared GitHub quota/backoff headers defer further release lookups without retries;
  expired metadata is never substituted for a latest lookup.
  Declared .NET Framework 3.5 requirements are checked read-only before artifact
  acquisition; this check never enables a Windows feature.

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
  Version: 0.22.0
  Changelog:
    0.22.0: Honor explicit EXE installer process-only completion without waiting for launched applications.
    0.21.0: Resolve NuGet package containers as ZIP-format portable artifacts.
    0.20.0: Detect declared per-user MSI products without ARP entries through Windows Installer registration.
    0.19.0: Fail closed on the declared shared .NET Framework 3.5 prerequisite.
    0.18.0: Preserve declared user data across package install/removal and retain installer-created collisions.
    0.17.0: Stage explicit installer configuration and preserve user data only after declared processes exit.
    0.16.0: Record rejected artifact evidence and relocate stale canonical sidecars.
    0.15.0: Quarantine artifacts that fail integrity/content checks so retries can reacquire.
    0.14.0: Check minimum versions of declared runtime DLL and installed package prerequisites.
    0.13.0: Check declared Windows system-DLL prerequisites before package acquisition.
    0.12.0: Accept engine-verified local portable payloads with no acquisition fallback.
    0.11.0: Add explicit GitHub PAT selection and credential-safe acceptance boundaries.
    0.10.0: Bound latest-release metadata reuse and defer shared GitHub quota exhaustion.
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


$script:ModuleVersion = '0.22.0'
$script:GitHubReleaseCache = @{}
$script:GitHubReleaseNotBefore = $null
$script:GitHubReleaseRate = $null
Import-Module (Join-Path $PSScriptRoot 'RIDE.InstallerInspection.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PublisherSources.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PackageSelection.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE-PortablePackages.psm1') -ErrorAction Stop

function Get-RideMsiRelatedProduct {
  param([Parameter(Mandatory)][string]$UpgradeCode,[Parameter(Mandatory)][string]$ProductName)
  $UpgradeCode='{' + $UpgradeCode.Trim('{}') + '}'
  if(-not ('RIDE.MsiProductLookup' -as [type])){
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
namespace RIDE {
public static class MsiProductLookup {
  [DllImport("msi.dll", CharSet=CharSet.Unicode, EntryPoint="MsiEnumRelatedProductsW")]
  private static extern uint MsiEnumRelatedProducts(string upgradeCode, uint reserved, uint index, StringBuilder productCode);
  [DllImport("msi.dll", CharSet=CharSet.Unicode, EntryPoint="MsiGetProductInfoW")]
  private static extern uint MsiGetProductInfo(string productCode, string property, StringBuilder value, ref uint length);
  public static string[] EnumerateRelatedProducts(string upgradeCode) {
    var products = new List<string>();
    for (uint index=0; index<256; index++) {
      var code = new StringBuilder(39);
      uint result = MsiEnumRelatedProducts(upgradeCode, 0, index, code);
      if (result == 259) break;
      if (result != 0) throw new InvalidOperationException("MsiEnumRelatedProducts failed with Windows Installer error " + result + ".");
      products.Add(code.ToString());
    }
    return products.ToArray();
  }
  public static string GetProductInfo(string productCode, string property) {
    uint length=512;
    var value = new StringBuilder((int)length);
    uint result = MsiGetProductInfo(productCode, property, value, ref length);
    if (result != 0) return null;
    return value.ToString();
  }
}
}
'@ -ErrorAction Stop
  }
  foreach($productCode in [RIDE.MsiProductLookup]::EnumerateRelatedProducts($UpgradeCode)){
    $name=[RIDE.MsiProductLookup]::GetProductInfo($productCode,'ProductName')
    $assignmentType=[RIDE.MsiProductLookup]::GetProductInfo($productCode,'AssignmentType')
    if($name -ceq $ProductName -and $assignmentType -ceq '0'){
      return [pscustomobject]@{
        ProductCode=$productCode
        DisplayName=$name
        DisplayVersion=[RIDE.MsiProductLookup]::GetProductInfo($productCode,'VersionString')
        AssignmentType=$assignmentType
      }
    }
  }
  $null
}

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
    $ownedMainRegistration = $false
    if ($Operation.OwnedConflictingInstallPath -and $Operation.InstallDirectory) {
      $ownedRelativePath = [string]$Operation.OwnedConflictingInstallPath
      if ($ownedRelativePath -cne '../GnuPG') { throw "Unsupported owned nested install path for '$($Operation.Id)'." }
      $ownedNestedPath = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $Operation.InstallDirectory) 'GnuPG'))
      $ownedMainRegistration = @(
        Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName -match $Operation.DisplayNamePattern -and [string]$_.InstallLocation -ieq [string]$Operation.InstallDirectory }
      ).Count -gt 0
    }
    $allRoots=@('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($root in $allRoots) {
      foreach ($entry in (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
        $isMainRegistration = $root -like 'HKCU:*' -and $entry.DisplayName -match $Operation.DisplayNamePattern -and [string]$entry.InstallLocation -ieq [string]$Operation.InstallDirectory
        $isOwnedNestedRegistration = $ownedMainRegistration -and $root -like 'HKCU:*' -and [string]$entry.InstallLocation -and
          [IO.Path]::GetFullPath([string]$entry.InstallLocation) -ieq $ownedNestedPath
        if ($entry.DisplayName -match $Operation.ConflictingDisplayNamePattern -and -not $isMainRegistration -and -not $isOwnedNestedRegistration) {
          throw "Conflicting existing edition or destination for '$($Operation.Id)': $($entry.DisplayName). Review it before migration."
        }
      }
    }
  }
  $uninstallRoots = if ($Operation.Scope -eq 'User') { @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') } else { @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  ) }
  $outdatedMatch = $null
  foreach ($root in $uninstallRoots) {
    foreach ($entry in (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
      if ($entry.DisplayName -match $Operation.DisplayNamePattern) {
        if ($Operation.MinimumInstalledVersion) {
          [version]$requiredVersion = [version]::MinValue
          [version]$detectedVersion = [version]::MinValue
          if (-not [version]::TryParse([string]$Operation.MinimumInstalledVersion, [ref]$requiredVersion) -or
              -not [version]::TryParse([string]$entry.DisplayVersion, [ref]$detectedVersion)) {
            continue
          }
          if ($detectedVersion -lt $requiredVersion) {
            if (-not $outdatedMatch) { $outdatedMatch = $entry }
            continue
          }
        }
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

  if($Operation.MsiUpgradeCode -and $Operation.MsiProductName -and $Operation.MsiInstallDirectoryRegistryKey){
    $vendor=Get-ItemProperty -LiteralPath $Operation.MsiInstallDirectoryRegistryKey -ErrorAction SilentlyContinue
    $installDirectory=[string]$vendor.InstallDir
    if($installDirectory){
      $installerProduct=Get-RideMsiRelatedProduct -UpgradeCode $Operation.MsiUpgradeCode -ProductName $Operation.MsiProductName
      $expectedDirectory=[IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Programs/' + $Operation.MsiInstallDirectory))).TrimEnd('\')
      $registeredDirectory=[IO.Path]::GetFullPath($installDirectory).TrimEnd('\')
      if($installerProduct -and $registeredDirectory -ieq $expectedDirectory -and
         (Test-Path -LiteralPath (Join-Path $installDirectory $Operation.MsiExecutable) -PathType Leaf)){
        return [pscustomobject]@{
          Present=$true
          DisplayName=$installerProduct.DisplayName
          DisplayVersion=$installerProduct.DisplayVersion
          UninstallString='"msiexec.exe" /x ' + $installerProduct.ProductCode
          QuietUninstallString=$null
          InstallLocation=$installDirectory
        }
      }
    }
  }

  if ($outdatedMatch) {
    return [pscustomobject]@{
      Present = $false
      DisplayName = $outdatedMatch.DisplayName
      DisplayVersion = $outdatedMatch.DisplayVersion
      UninstallString = $outdatedMatch.UninstallString
      QuietUninstallString = $outdatedMatch.QuietUninstallString
      InstallLocation = $outdatedMatch.InstallLocation
    }
  }
  [pscustomobject]@{ Present = $false; DisplayName = $null; DisplayVersion = $null; UninstallString = $null; QuietUninstallString = $null; InstallLocation = $null }
}

function Get-RideSysmonInstallRoot {
  Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RIDE/Programs/Sysmon'
}

function Get-RideGitHubUtcNow { [DateTime]::UtcNow }

function Get-RideGitHubHeader {
  param($Headers, [string] $Name)
  if ($null -eq $Headers) { return $null }
  if ($Headers -is [Collections.IDictionary]) { return (@($Headers[$Name]) -join ',') }
  if ($Headers -is [Collections.Specialized.NameValueCollection]) { return $Headers.Get($Name) }
  if ($Headers.PSObject.Methods['Contains'] -and $Headers.PSObject.Methods['GetValues']) {
    if ($Headers.Contains($Name)) { return ($Headers.GetValues($Name) -join ',') }
  }
  return $null
}

function Get-RideGitHubRate {
  param($Headers)
  $remaining = 0L; $reset = 0L; $retry = 0L
  $hasRemaining = [long]::TryParse((Get-RideGitHubHeader $Headers 'X-RateLimit-Remaining'), [ref]$remaining) -and $remaining -ge 0
  $hasReset = [long]::TryParse((Get-RideGitHubHeader $Headers 'X-RateLimit-Reset'), [ref]$reset) -and $reset -ge 0
  $hasRetry = [long]::TryParse((Get-RideGitHubHeader $Headers 'Retry-After'), [ref]$retry) -and $retry -ge 0
  $resetAt = $null
  if ($hasReset) {
    try { $resetAt = ([DateTime]::SpecifyKind([DateTime]'1970-01-01', [DateTimeKind]::Utc)).AddSeconds($reset) } catch { }
  }
  [pscustomobject]@{
    Remaining = if ($hasRemaining) { $remaining } else { $null }
    ResetAtUtc = $resetAt
    RetryAfterSeconds = if ($hasRetry) { $retry } else { $null }
  }
}

function Set-RideGitHubBackoff {
  param($Rate, [DateTime] $Now)
  # Unknown/expired headers still require a bounded, one-minute pause. Never spin.
  $deadline = $Now.AddSeconds(60)
  if ($Rate.Remaining -eq 0 -and $Rate.ResetAtUtc -and $Rate.ResetAtUtc -ge $Now) {
    try { $deadline = $Rate.ResetAtUtc.AddSeconds(1) } catch { }
  }
  if ($null -ne $Rate.RetryAfterSeconds) {
    try {
      $retryAt = $Now.AddSeconds($Rate.RetryAfterSeconds)
      if ($retryAt -gt $deadline) { $deadline = $retryAt }
    } catch { }
  }
  $script:GitHubReleaseNotBefore = $deadline
  $script:GitHubReleaseRate = $Rate
}

function Stop-RideGitHubReleaseLookup {
  param([string] $Uri)
  $remaining = if ($null -ne $script:GitHubReleaseRate.Remaining) { [string]$script:GitHubReleaseRate.Remaining } else { 'unknown' }
  $reset = if ($script:GitHubReleaseRate.ResetAtUtc) { $script:GitHubReleaseRate.ResetAtUtc.ToString('o') } else { 'unknown' }
  throw "GitHub release acquisition deferred for $Uri. Remaining quota: $remaining; reset UTC: $reset; retry no earlier than $($script:GitHubReleaseNotBefore.ToString('o')). No expired metadata or automatic retry was used."
}

function Get-RideGitHubReleaseMetadata {
  param([Parameter(Mandatory)][string] $Uri, [ValidateSet('Anonymous','PAT')][string] $GitHubAuthentication = 'Anonymous', [string] $GitHubCredentialReference)
  if (($GitHubAuthentication -eq 'PAT') -ne (-not [string]::IsNullOrWhiteSpace($GitHubCredentialReference))) { throw 'PAT requires an explicit GitHubCredentialReference; Anonymous forbids one.' }
  if ($GitHubAuthentication -eq 'PAT') {
    Import-Module (Join-Path $PSScriptRoot 'RIDE.GitHubAuthentication.psm1') -ErrorAction Stop
    return Get-RideAuthenticatedGitHubRelease -Uri $Uri -CredentialReference $GitHubCredentialReference -Cache $script:GitHubReleaseCache
  }
  $endpoint = $null
  if (-not [Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$endpoint) -or
      $endpoint.Scheme -ne 'https' -or $endpoint.Host -ne 'api.github.com' -or
      -not $endpoint.IsDefaultPort -or $endpoint.UserInfo -or $endpoint.Query -or $endpoint.Fragment -or
      $endpoint.AbsolutePath -notmatch '^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/(?:latest|tags/[A-Za-z0-9][A-Za-z0-9.+_-]*)$') {
    throw 'GitHub release discovery must identify a latest or exact tagged release on the public HTTPS API without credentials or query parameters.'
  }
  $key = $endpoint.AbsoluteUri
  $now = Get-RideGitHubUtcNow
  # Serialize cached bodies so callers cannot mutate a later resolution's input.
  foreach ($expired in @($script:GitHubReleaseCache.Keys)) {
    $entry = $script:GitHubReleaseCache[$expired]
    if ($now -lt $entry.RetrievedAtUtc -or $now -ge $entry.ExpiresAtUtc) { $script:GitHubReleaseCache.Remove($expired) }
  }
  $entry = $script:GitHubReleaseCache[$key]
  $kind = 'ProcessCache'
  if (-not $entry) {
    if ($script:GitHubReleaseNotBefore -and $now -lt $script:GitHubReleaseNotBefore) { Stop-RideGitHubReleaseLookup $key }
    $script:GitHubReleaseNotBefore = $null
    $script:GitHubReleaseRate = $null
    try {
      $response = Invoke-WebRequest -Uri $key -UseBasicParsing -TimeoutSec 120 -MaximumRedirection 0 -Headers @{
        Accept = 'application/vnd.github+json'; 'User-Agent' = 'RIDE-Windows'
      } -ErrorAction Stop
    } catch {
      $httpResponse = $_.Exception.Response
      $rate = Get-RideGitHubRate $httpResponse.Headers
      $status = if ($httpResponse) { [int]$httpResponse.StatusCode } else { 0 }
      if ($status -eq 429 -or ($status -eq 403 -and
          ($rate.Remaining -eq 0 -or $null -ne $rate.RetryAfterSeconds -or $_.ErrorDetails.Message -match '(?i)rate limit'))) {
        Set-RideGitHubBackoff $rate (Get-RideGitHubUtcNow)
        Stop-RideGitHubReleaseLookup $key
      }
      throw
    }
    $now = Get-RideGitHubUtcNow
    $rate = Get-RideGitHubRate $response.Headers
    if ($rate.Remaining -eq 0) { Set-RideGitHubBackoff $rate $now }
    $json = [string]$response.Content
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 2MB) { throw 'GitHub release metadata exceeds the two MiB cache limit.' }
    $release = $json | ConvertFrom-Json -ErrorAction Stop
    if (-not $release.tag_name -or 'assets' -notin $release.PSObject.Properties.Name) { throw 'GitHub release metadata requires a release tag and assets.' }
    $entry = [pscustomobject]@{ Json = $json; RetrievedAtUtc = $now; ExpiresAtUtc = $now.AddMinutes(5); Rate = $rate }
    # Fixed limits avoid an unbounded cache when external libraries add products.
    if ($script:GitHubReleaseCache.Count -ge 64) {
      $oldest = $script:GitHubReleaseCache.GetEnumerator() | Sort-Object { $_.Value.RetrievedAtUtc } | Select-Object -First 1
      $script:GitHubReleaseCache.Remove($oldest.Key)
    }
    $script:GitHubReleaseCache[$key] = $entry
    $kind = 'Network'
  }
  [pscustomobject]@{
    Release = ($entry.Json | ConvertFrom-Json -ErrorAction Stop)
    Provenance = [pscustomobject]@{
      ApiUri = $key; AcquisitionKind = $kind; AuthenticationMode = 'Anonymous'
      RetrievedAtUtc = $entry.RetrievedAtUtc.ToString('o'); ExpiresAtUtc = $entry.ExpiresAtUtc.ToString('o')
      RemainingQuota = $entry.Rate.Remaining
      ResetAtUtc = if ($entry.Rate.ResetAtUtc) { $entry.Rate.ResetAtUtc.ToString('o') } else { $null }
    }
  }
}

function Resolve-RidePackageArtifact {
  <#
  .SYNOPSIS
    Resolve the catalog source to a versioned upstream artifact.

  .DESCRIPTION
    Resolves an explicit versioned HTTPS installer, a latest or exact tagged GitHub release API,
    immutable GitHub file commit or Microsoft Sysmon page.
    Validates source/asset metadata and returns available digest/signature links. Makes network
    requests but does not download/install the artifact. GitHub latest-release metadata
    may be reused for five minutes within this process; expired data is never a fallback.
    Quota exhaustion defers acquisition and reports the shared backoff deadline.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER GitHubAuthentication
    Anonymous (default) or explicit PAT for GitHub release discovery only.

  .PARAMETER GitHubCredentialReference
    Nonsecret enrolled reference required with PAT. Resolved only during acquisition.

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

  param([Parameter(Mandatory = $true)][hashtable] $Operation, [ValidateSet('Anonymous','PAT')][string] $GitHubAuthentication = 'Anonymous', [string] $GitHubCredentialReference)

  if ($Operation.AcquisitionBlockedReason) { throw "Acquisition blocked for $($Operation.PackageId): $($Operation.AcquisitionBlockedReason)" }
  if ($Operation.DownloadProvider -eq 'JoeWareAdModForm') {
    $productUri = 'https://www.joeware.net/freetools/tools/admod/index.htm'
    if ($Operation.PackageId -cne 'joeware-admod' -or $Operation.AcquisitionProduct -cne 'admod' -or
        $Operation.ProductUri -cne $productUri -or $Operation.DownloadUri -cne $productUri -or
        $Operation.AssetName -cne 'AdMod.zip' -or $Operation.InstallerType -cne 'Portable' -or
        $Operation.PortableFormat -cne 'Zip' -or $Operation.Architecture -cne 'x86' -or
        $Operation.PackageVersion -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]*$' -or
        $Operation.ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$' -or
        @($Operation.PortableMembers).Count -ne 1 -or $Operation.PortableMembers[0] -cne 'AdMod.exe' -or
        @($Operation.RequiredFiles).Count -ne 1 -or $Operation.RequiredFiles[0] -cne 'AdMod.exe') {
      throw 'JoeWare product-form packages require the pinned AdMod publisher page, ZIP member, version, architecture, and SHA-256 metadata.'
    }
    return [pscustomobject]@{
      PackageId = [string]$Operation.PackageId
      OriginUri = $productUri
      Version = [string]$Operation.PackageVersion
      Architecture = 'x86'
      FileName = 'AdMod.zip'
      Uri = $productUri
      SourceUri = $productUri
      ProviderDigest = 'sha256:' + ([string]$Operation.ExpectedSha256).ToLowerInvariant()
      ChecksumUris = @('https://www.joeware.net/freetools/versions.txt')
      SignatureUris = @()
    }
  }
  if ($Operation.DownloadProvider -in @('VSCodeUpdateApi', 'MozillaVersionsJson', 'PublisherLinkPage', 'SignalDesktopFeed', 'WinSCPPortablePage')) { return Resolve-RidePublisherArtifact -Operation $Operation }
  if ($Operation.DownloadProvider -eq 'GitHubReleaseAssetApi') {
    $repository=[string]$Operation.Repository
    $releaseTag=[string]$Operation.ReleaseTag
    $assetName=[string]$Operation.AssetName
    $releaseVersion=[string]$Operation.PackageVersion
    $targetVersion=[string]$Operation.TargetSysmonVersion
    $expectedRepository='olafhartong/sysmon-modular'
    $expectedTag='configs-'+$releaseVersion
    $allowedAssets=@('sysmonconfig.xml','sysmonconfig-with-filedelete.xml','sysmonconfig-excludes-only.xml')
    if($repository -cne $expectedRepository -or $releaseVersion -notmatch '^[0-9a-f]{12}$' -or $releaseTag -cne $expectedTag -or $targetVersion -cne '15.21' -or $assetName -notin $allowedAssets -or $Operation.Architecture -cne 'neutral') { throw 'Sysmon Modular release metadata must pin one reviewed profile from the exact 15.21 configuration release.' }
    $expectedDownloadUri="https://github.com/$repository/releases/download/$releaseTag/$assetName"
    $expectedChecksumUri="https://github.com/$repository/releases/download/$releaseTag/SHA256SUMS"
    if($Operation.DownloadUri -cne $expectedDownloadUri -or $Operation.ChecksumUri -cne $expectedChecksumUri) { throw 'Sysmon Modular profile URLs must match the pinned repository, release tag, profile and checksum manifest.' }
    $manifestResponse=Invoke-WebRequest -Uri $expectedChecksumUri -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    $manifest=[string]$manifestResponse.Content
    if($manifest.Length -gt 1048576) { throw 'Sysmon Modular SHA256SUMS response exceeds 1 MiB.' }
    $matchingLines=@($manifest -split "`r?`n" | Where-Object { $_ -match ('^\s*[0-9a-fA-F]{64}\s+\*?'+[regex]::Escape($assetName)+'\s*$') })
    if($matchingLines.Count -ne 1) { throw "Expected exactly one checksum record for $assetName in the pinned Sysmon Modular release." }
    $digestMatch=[regex]::Match($matchingLines[0],'^\s*(?<hash>[0-9a-fA-F]{64})\s+\*?(?<file>[^\s]+)\s*$')
    if(-not $digestMatch.Success -or $digestMatch.Groups['file'].Value -cne $assetName) { throw 'Sysmon Modular checksum record does not match the selected profile filename.' }
    $digest=$digestMatch.Groups['hash'].Value.ToLowerInvariant()
    return [pscustomobject]@{
      PackageId = [string]$Operation.ArtifactId
      ArtifactId = [string]$Operation.ArtifactId
      OriginUri = [string]$Operation.ProductUri
      Version = $releaseVersion
      Architecture = 'neutral'
      FileName = $assetName
      Uri = $expectedDownloadUri
      SourceUri = $expectedChecksumUri
      ProviderDigest = 'sha256:'+$digest
      ChecksumUris = @($expectedChecksumUri)
      SignatureUris = @()
    }
  }
  if ($Operation.DownloadProvider -eq 'MicrosoftOpenJdk') {
    $version=[string]$Operation.PackageVersion
    $architecture=[string]$Operation.Architecture
    if ($version -notmatch '^(?:11|17|21|25)\.0\.[0-9]+\.[0-9]+$' -or $architecture -cne 'x64' -or $Operation.InstallerType -cne 'Msi') { throw 'Microsoft OpenJDK requires a pinned LTS version and x64 Windows MSI.' }
    $fileName="microsoft-jdk-$version-windows-x64.msi"
    $expectedDownloadUri="https://aka.ms/download-jdk/$fileName"
    $expectedChecksumUri="$expectedDownloadUri.sha256sum.txt"
    if ($Operation.AssetName -cne $fileName -or $Operation.DownloadUri -cne $expectedDownloadUri -or $Operation.ExpectedSha256Uri -cne $expectedChecksumUri) { throw 'Microsoft OpenJDK source URLs must match the exact pinned versioned x64 MSI and its official checksum file.' }
    $checksumResponse=Invoke-WebRequest -Uri $expectedChecksumUri -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    $responseContent=$checksumResponse.Content
    if ($responseContent -is [byte[]]) {
      if ($responseContent.Length -gt 4096) { throw 'Microsoft OpenJDK checksum response exceeds 4 KiB.' }
      $content=[Text.Encoding]::UTF8.GetString($responseContent)
    } else {
      $content=[string]$responseContent
      if ($content.Length -gt 4096) { throw 'Microsoft OpenJDK checksum response exceeds 4 KiB.' }
    }
    $content=$content.TrimStart([char]0xFEFF).Trim()
    $lines=@($content -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -ne 1) { throw 'Expected exactly one Microsoft OpenJDK checksum record.' }
    $checksumMatch=[regex]::Match($lines[0],'^\s*(?:SHA-?256\s*\((?<name>[^)]+)\)\s*=\s*)?(?<hash>[0-9a-fA-F]{64})(?:\s+\*?(?<file>[^\s]+))?\s*$')
    if (-not $checksumMatch.Success) {
      $sample=$lines[0].Substring(0,[Math]::Min(160,$lines[0].Length)) -replace '[\x00-\x1F\x7F]',' '
      $contentType=if($checksumResponse.Headers){[string]$checksumResponse.Headers['Content-Type']}else{''}
      throw "Microsoft OpenJDK checksum response does not contain one supported SHA-256 record (content type='$contentType'; sample='$sample')."
    }
    $checksumName=if($checksumMatch.Groups['name'].Success){$checksumMatch.Groups['name'].Value}else{$checksumMatch.Groups['file'].Value}
    if($checksumName -and [IO.Path]::GetFileName($checksumName) -cne $fileName){throw 'Microsoft OpenJDK checksum record names a different file.'}
    $digest=$checksumMatch.Groups['hash'].Value.ToLowerInvariant()
    return [pscustomobject]@{
      PackageId = [string]$Operation.PackageId
      OriginUri = [string]$Operation.ProductUri
      Version = $version
      Architecture = $architecture
      FileName = $fileName
      Uri = $expectedDownloadUri
      SourceUri = $expectedChecksumUri
      ProviderDigest = 'sha256:' + $digest
      ChecksumUris = @($expectedChecksumUri)
      SignatureUris = @()
    }
  }

  if ($Operation.DownloadProvider -eq 'DirectHttps') {
    if (-not [uri]::IsWellFormedUriString([string]$Operation.DownloadUri, [UriKind]::Absolute)) { throw 'A direct installer requires an absolute HTTPS URL.' }
    $source = [uri]$Operation.DownloadUri
    if ($source.Scheme -ne 'https' -or -not $source.IsDefaultPort -or $source.UserInfo -or $source.Fragment) { throw 'A direct installer requires HTTPS on the default port without credentials or fragments.' }
    $assetNameExtension = [IO.Path]::GetExtension([string]$Operation.AssetName)
    $assetExtension = if ($Operation.PortableFormat -eq 'File') { $assetNameExtension } elseif ($Operation.PortableFormat -eq 'SevenZip') { '.7z' } elseif ($Operation.ArchiveType -eq 'Zip' -or $Operation.PortableFormat -eq 'Zip') { if ($assetNameExtension -eq '.nupkg' -and $Operation.InstallerType -eq 'Portable' -and $Operation.PortableFormat -eq 'Zip') { '.nupkg' } else { '.zip' } } else { '.' + ([string]$Operation.InstallerType).ToLowerInvariant() }
    $assetPattern = if ($assetExtension -eq '.nupkg') { '^[a-zA-Z0-9][a-zA-Z0-9._-]*\.nupkg$' } else { '^[a-zA-Z0-9][a-zA-Z0-9._-]*\.(exe|msi|zip|7z)$' }
    if ($Operation.ArchiveType -and $Operation.ArchiveType -notin @('None', 'Zip')) { throw 'Unsupported ArchiveType.' }
    if ($Operation.ArchiveType -eq 'Zip' -and $Operation.InstallerType -ne 'Portable') {
      $entry = [string]$Operation.InstallerEntry
      if (-not $entry -or $entry.Length -gt 240 -or $entry -match '[\\\x00-\x1f:"*?<>|]|^/|(^|/)\.{1,2}(/|$)|[. ](/|$)|//|/$' -or
          [IO.Path]::GetExtension($entry) -ne ('.' + ([string]$Operation.InstallerType).ToLowerInvariant())) { throw 'ZIP requires a safe matching EXE/MSI InstallerEntry.' }
      if ($Operation.ContainsKey('ExpectedInstallerSha256') -and $Operation.ExpectedInstallerSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'ExpectedInstallerSha256 must contain 64 hexadecimal characters.' }
    } elseif ($Operation.ContainsKey('InstallerEntry') -or $Operation.ContainsKey('ExpectedInstallerSha256')) { throw 'InstallerEntry and ExpectedInstallerSha256 require ArchiveType Zip.' }
    if ($Operation.PackageVersion -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]*$' -or
        $Operation.InstallerType -notin @('Exe', 'Msi', 'Portable') -or
        $Operation.AssetName -notmatch $assetPattern -or
        [IO.Path]::GetExtension([string]$Operation.AssetName) -ne $assetExtension) { throw 'A direct installer requires a safe version and an EXE/MSI/ZIP/7z filename matching its metadata.' }
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
  $repositoryMatch = [regex]::Match(([uri]$Operation.DownloadUri).AbsolutePath, '^/repos/(?<repository>[^/]+/[^/]+)/releases/(?<release>latest|tags/(?<tag>[A-Za-z0-9][A-Za-z0-9.+_-]*))$')
  if (-not $repositoryMatch.Success) { throw 'GitHub release discovery must identify the declared publisher repository.' }
  $repository = $repositoryMatch.Groups['repository'].Value
  $exactTag = [string]$Operation.ReleaseTag
  $publisherChecksum = $null
  if ($exactTag) {
    $declaredVersion = [regex]::Replace($exactTag, '^v', '')
    if ($exactTag -notmatch '^[A-Za-z0-9][A-Za-z0-9.+_-]*$' -or $repositoryMatch.Groups['tag'].Value -cne $exactTag -or
        $Operation.DownloadUri -cne "https://api.github.com/repos/$repository/releases/tags/$exactTag" -or
        ($Operation.Repository -and [string]$Operation.Repository -cne $repository) -or
        [string]$Operation.PackageVersion -cne $declaredVersion -or
        -not $Operation.AssetName -or [string]$Operation.AssetName -notmatch [string]$Operation.AssetPattern -or
        -not $Operation.ChecksumAssetName -or [string]$Operation.ChecksumAssetName -cne ([string]$Operation.AssetName + '.sha256')) {
      throw "Pinned GitHub release metadata for $($Operation.PackageId) must name one exact repository, tag, asset and checksum asset."
    }
  } elseif ($repositoryMatch.Groups['release'].Value -cne 'latest') {
    throw 'GitHub release API URI must use releases/latest unless an exact ReleaseTag is declared.'
  }
  $metadata = Get-RideGitHubReleaseMetadata -Uri $Operation.DownloadUri -GitHubAuthentication $GitHubAuthentication -GitHubCredentialReference $GitHubCredentialReference
  $release = $metadata.Release
  if ($exactTag -and [string]$release.tag_name -cne $exactTag) { throw "GitHub returned a different release tag for $($Operation.PackageId)." }
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
  $assetUri = [uri]$uri
  $publisherPrefix = '/' + $repository + '/releases/download/'
  if ($assetUri.Host -ne 'github.com' -or -not $assetUri.IsDefaultPort -or $assetUri.UserInfo -or -not $assetUri.AbsolutePath.StartsWith($publisherPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The release asset for $($Operation.PackageId) must come from the declared publisher repository."
  }
  if ($exactTag) {
    if ([string]$asset.name -cne [string]$Operation.AssetName -or $assetUri.AbsolutePath -notmatch ('/releases/download/' + [regex]::Escape($exactTag) + '/' + [regex]::Escape([string]$Operation.AssetName) + '$')) {
      throw "The asset for $($Operation.PackageId) does not match its exact pinned release tag and filename."
    }
    $checksumAsset = @($release.assets | Where-Object { $_.name -ceq [string]$Operation.ChecksumAssetName })
    if ($checksumAsset.Count -ne 1) { throw "Expected exactly one pinned checksum asset for $($Operation.PackageId)." }
    $checksumUri = [uri][string]$checksumAsset[0].browser_download_url
    if ($checksumUri.Scheme -ne 'https' -or $checksumUri.Host -ne 'github.com' -or $checksumUri.UserInfo -or
        -not $checksumUri.AbsolutePath.StartsWith($publisherPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $checksumUri.AbsolutePath -notmatch ('/releases/download/' + [regex]::Escape($exactTag) + '/' + [regex]::Escape([string]$Operation.ChecksumAssetName) + '$')) {
      throw "The checksum asset for $($Operation.PackageId) is not from the exact pinned publisher release."
    }
    $checksumResponse = Invoke-WebRequest -Uri $checksumUri.AbsoluteUri -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    $checksumText = [string]$checksumResponse.Content
    if ([Text.Encoding]::UTF8.GetByteCount($checksumText) -gt 4096) { throw "The publisher checksum for $($Operation.PackageId) exceeds 4 KiB." }
    $checksumLines = @($checksumText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($checksumLines.Count -ne 1) { throw "Expected exactly one SHA-256 record for $($Operation.AssetName)." }
    $checksumMatch = [regex]::Match($checksumLines[0], '^\s*(?:(?<hash>[a-fA-F0-9]{64})\s+\*?(?<file>[^\s]+)|SHA-?256\s*\((?<name>[^)]+)\)\s*=\s*(?<hash2>[a-fA-F0-9]{64})|(?<hash3>[a-fA-F0-9]{64}))\s*$')
    if (-not $checksumMatch.Success) { throw "Publisher checksum for $($Operation.PackageId) is not one valid SHA-256 record." }
    $checksumFile = if ($checksumMatch.Groups['file'].Success) { $checksumMatch.Groups['file'].Value } elseif ($checksumMatch.Groups['name'].Success) { $checksumMatch.Groups['name'].Value } else { $null }
    $publisherChecksum = if ($checksumMatch.Groups['hash'].Success) { $checksumMatch.Groups['hash'].Value } elseif ($checksumMatch.Groups['hash2'].Success) { $checksumMatch.Groups['hash2'].Value } else { $checksumMatch.Groups['hash3'].Value }
    if ($checksumFile -and [IO.Path]::GetFileName($checksumFile) -cne [string]$Operation.AssetName) { throw "Publisher checksum names a different file than $($Operation.AssetName)." }
    $publisherChecksum = $publisherChecksum.ToLowerInvariant()
  }
  $version = [string]$release.tag_name
  if ($Operation.TagPrefix -and $version.StartsWith([string]$Operation.TagPrefix, [StringComparison]::Ordinal)) { $version = $version.Substring(([string]$Operation.TagPrefix).Length) }
  if ($version.StartsWith('v', [StringComparison]::OrdinalIgnoreCase)) { $version = $version.Substring(1) }
  if (-not $version -or $version -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]*$') { throw "The release tag for $($Operation.PackageId) has an invalid version." }
  if ($exactTag -and [string]$Operation.PackageVersion -cne $version) { throw "Pinned GitHub release tag $exactTag does not match PackageVersion for $($Operation.PackageId)." }

  if ($Operation.PublisherChecksumSource -eq 'ReleaseNotes' -and -not $exactTag) {
    $escapedName = [regex]::Escape([string]$asset.name)
    $checksumMatches = @([regex]::Matches([string]$release.body, "(?im)^\s*\|?\s*${escapedName}\s*\|\s*([0-9a-f]{64})\s*\|?\s*$|^\s*([0-9a-f]{64})\s+${escapedName}\s*$"))
    $checksums = @($checksumMatches | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value.ToLowerInvariant() } else { $_.Groups[2].Value.ToLowerInvariant() } } | Select-Object -Unique)
    if ($checksums.Count -gt 1) { throw "Conflicting publisher checksums for $($asset.name)." }
    if ($checksums.Count -eq 1) { $publisherChecksum = $checksums[0] }
  }
  [pscustomobject]@{
    PackageId = [string]$Operation.PackageId
    OriginUri = if ($Operation.ProductUri) { [string]$Operation.ProductUri } else { 'https://github.com/' + $repository }
    Version = $version
    Architecture = [string]$Operation.Architecture
    FileName = [string]$asset.name
    Uri = $uri
    SourceUri = [string]$release.html_url
    ReleaseMetadata = $metadata.Provenance
    ProviderDigest = [string]$asset.digest
    PublisherSha256 = $publisherChecksum
    PublisherChecksumUri = if ($publisherChecksum -and $exactTag) { $checksumUri.AbsoluteUri } elseif ($publisherChecksum) { [string]$release.html_url } else { $null }
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

function Move-RideRejectedPackageArtifact {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][pscustomobject]$Artifact,[Parameter(Mandatory)][string]$Reason)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($item.PSIsContainer) { throw 'Rejected artifact path unexpectedly names a directory.' }
  $rejectedPath = $Path + '.rejected-' + [guid]::NewGuid().ToString('N')
  [IO.File]::Move([IO.Path]::GetFullPath($Path), [IO.Path]::GetFullPath($rejectedPath))
  $evidenceError = $null
  $previousSidecarPath = $Path + '.ride.json'
  $preservedPreviousSidecarPath = $null
  if (Test-Path -LiteralPath $previousSidecarPath -PathType Leaf) {
    $preservedPreviousSidecarPath = $rejectedPath + '.previous.ride.json'
    try { [IO.File]::Move([IO.Path]::GetFullPath($previousSidecarPath), [IO.Path]::GetFullPath($preservedPreviousSidecarPath)) }
    catch { $evidenceError = "Could not move the previous canonical observation sidecar: $($_.Exception.Message)" }
  }
  $sidecarPath = $rejectedPath + '.ride.json'
  try {
    $rejectedItem = Get-Item -LiteralPath $rejectedPath -Force -ErrorAction Stop
    $record = [ordered]@{
      SchemaVersion = 1
      Kind = 'RejectedPackageArtifact'
      RejectedAtUtc = [DateTime]::UtcNow.ToString('o')
      PackageId = $Artifact.PackageId
      ArtifactId = $Artifact.ArtifactId
      Version = $Artifact.Version
      Architecture = $Artifact.Architecture
      OriginalFileName = $Artifact.FileName
      RejectedFileName = [IO.Path]::GetFileName($rejectedPath)
      Uri = $Artifact.Uri
      SourceUri = $Artifact.SourceUri
      Reason = $Reason
      Sha256 = (Get-FileHash -LiteralPath $rejectedPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
      FileSize = $rejectedItem.Length
      PreviousObservationPreservedAt = if ($preservedPreviousSidecarPath -and (Test-Path -LiteralPath $preservedPreviousSidecarPath -PathType Leaf)) { [IO.Path]::GetFileName($preservedPreviousSidecarPath) } else { $null }
    }
    $bytes = [Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject ([pscustomobject]$record) -Depth 6 -Compress))
    $stream = [IO.File]::Open($sidecarPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  }
  catch {
    $message = "Could not write rejected-artifact evidence sidecar: $($_.Exception.Message)"
    $evidenceError = if ($evidenceError) { $evidenceError + ' ' + $message } else { $message }
    $sidecarPath = $null
  }
  [pscustomobject]@{Path=$rejectedPath;SidecarPath=$sidecarPath;PreviousSidecarPath=$preservedPreviousSidecarPath;EvidenceError=$evidenceError}
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
    ReleaseMetadata = $Artifact.ReleaseMetadata
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
    Artifacts failing digest, archive-content, or signature-integrity checks are moved out of the
    reusable canonical cache path under a unique rejected name with a hash/reason sidecar; their
    bytes are retained, and any previous canonical observation moves beside them.
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

  .PARAMETER GitHubAuthentication
    Anonymous (default) or explicit PAT for GitHub release discovery only.

  .PARAMETER GitHubCredentialReference
    Nonsecret enrolled reference required with PAT. Resolved only during acquisition.

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
    [string] $Route = 'direct',
    [ValidateSet('Anonymous','PAT')][string] $GitHubAuthentication = 'Anonymous',
    [string] $GitHubCredentialReference
  )

  $Operation = Resolve-RidePackageSelection -Operation $Operation
  $artifact = Resolve-RidePackageArtifact -Operation $Operation -GitHubAuthentication $GitHubAuthentication -GitHubCredentialReference $GitHubCredentialReference
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
      if ($Operation.DownloadProvider -eq 'JoeWareAdModForm') {
        $stageDirectory = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-JoeWare-' + [guid]::NewGuid().ToString('N'))
        $downloadScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/Download-JoeWareCollection.ps1'
        try {
          if (-not (Test-Path -LiteralPath $downloadScript -PathType Leaf)) { throw 'The reviewed JoeWare acquisition script is unavailable.' }
          $downloadResults = @(& $downloadScript -Product $Operation.AcquisitionProduct -DestinationDirectory $stageDirectory -Confirm:$false -ErrorAction Stop)
          $sourceObservation = @($downloadResults | Where-Object { $_.Product -ceq 'admod' -and $_.PageVersion -ceq $artifact.Version -and $_.FileName -ceq $artifact.FileName })
          if ($sourceObservation.Count -ne 1) { throw 'JoeWare did not return exactly one current AdMod observation matching the pinned package version and file name.' }
          if ([string]$sourceObservation[0].Sha256 -ine [string]$Operation.ExpectedSha256) { throw 'JoeWare AdMod archive SHA-256 differs from the pinned catalog digest.' }
          $sourceArchive = Join-Path $stageDirectory $artifact.FileName
          if (-not (Test-Path -LiteralPath $sourceArchive -PathType Leaf)) { throw 'JoeWare did not retain the observed AdMod archive.' }
          Copy-Item -LiteralPath $sourceArchive -Destination $temporaryDownload -ErrorAction Stop
        }
        finally {
          if (Test-Path -LiteralPath $stageDirectory) {
            $resolvedStage = (Resolve-Path -LiteralPath $stageDirectory -ErrorAction Stop).Path
            if ($resolvedStage -ne [IO.Path]::GetFullPath($stageDirectory) -or (Split-Path -Leaf $resolvedStage) -notmatch '^RIDE-JoeWare-[0-9a-f]{32}$') { throw 'Unexpected JoeWare acquisition staging directory.' }
            Remove-Item -LiteralPath $resolvedStage -Recurse -Force
          }
        }
      }
      else { Invoke-WebRequest @downloadParameters }
      if (-not (Test-Path -LiteralPath $temporaryDownload -PathType Leaf) -or (Get-Item -LiteralPath $temporaryDownload).Length -eq 0) { throw 'Publisher returned an empty artifact.' }
      Move-Item -LiteralPath $temporaryDownload -Destination $installer -ErrorAction Stop
    } finally {
      if (Test-Path -LiteralPath $temporaryDownload -PathType Leaf) { Remove-Item -LiteralPath $temporaryDownload -Force }
    }
    $acquisitionKind = 'Download'
  }
  $artifact | Add-Member -NotePropertyName AcquisitionKind -NotePropertyValue $acquisitionKind -Force
  $contents = @()
  try {
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
  }
  catch {
    $validationMessage = $_.Exception.Message
    try { $rejected = Move-RideRejectedPackageArtifact -Path $installer -Artifact $artifact -Reason $validationMessage }
    catch { throw "Artifact validation failed ($validationMessage), and its bytes could not be moved aside from the reusable cache path: $($_.Exception.Message)" }
    if ($rejected) {
      $evidenceNote = if ($rejected.SidecarPath) { " Rejection evidence: '$($rejected.SidecarPath)'" } else { " Rejected-artifact evidence sidecar could not be written." }
      if ($rejected.PreviousSidecarPath -and (Test-Path -LiteralPath $rejected.PreviousSidecarPath -PathType Leaf)) { $evidenceNote += " Previous observation retained at '$($rejected.PreviousSidecarPath)'" }
      if ($rejected.EvidenceError) { $evidenceNote += " $($rejected.EvidenceError)" }
      throw "$validationMessage Rejected bytes retained at '$($rejected.Path)'; a later acquisition can use the canonical versioned cache path.$evidenceNote"
    }
    throw
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
    ReleaseMetadata = $artifact.ReleaseMetadata
    SelectedVariant = $artifact.SelectedVariant
    DownloadProvider = $artifact.DownloadProvider
    SourceUri = $artifact.SourceUri
    OriginUri = $artifact.OriginUri
    PublisherSha256 = $artifact.PublisherSha256
    PublisherChecksumUri = $artifact.PublisherChecksumUri
    ChecksumUris = @($artifact.ChecksumUris)
    SignatureUris = @($artifact.SignatureUris)
    FileEvidence = $fileEvidence
    License = $artifact.License
    LicenseUri = $artifact.LicenseUri
    TermsUri = $artifact.TermsUri
  }
}

function Get-RidePackagePrerequisiteStatus {
  param([Parameter(Mandatory = $true)][hashtable] $Operation)
  $failures = New-Object System.Collections.Generic.List[string]
  $prerequisiteDirectory = $null
  if ($Operation.PrerequisiteDotNetFramework35 -eq $true -and -not (Test-RideDotNetFramework35Installed)) {
    $failures.Add('requires the shared .NET Framework 3.5 feature, which supplies the CLR 2.0 runtime')
  }
  if ($Operation.ContainsKey('PrerequisiteSystemFiles')) {
    foreach ($fileName in $Operation.PrerequisiteSystemFiles) {
      if ($fileName -notmatch '^[A-Za-z0-9_.-]+\.dll$') { throw 'Invalid package system-file prerequisite.' }
      $systemFile = Join-Path (Join-Path $env:SystemRoot 'System32') $fileName
      if (-not (Test-Path -LiteralPath $systemFile -PathType Leaf)) {
        $failures.Add("requires the Windows system prerequisite '$fileName' at '$systemFile'")
        continue
      }
      if ($Operation.PrerequisiteSystemFileMinimumVersions -and $Operation.PrerequisiteSystemFileMinimumVersions.ContainsKey($fileName)) {
        $minimumVersion = [version]$Operation.PrerequisiteSystemFileMinimumVersions[$fileName]
        [version]$actualVersion = [version]::MinValue
        try { $fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($systemFile).FileVersion }
        catch { $failures.Add("cannot read version for '$systemFile': $($_.Exception.Message)"); continue }
        if (-not [version]::TryParse([string]$fileVersion, [ref]$actualVersion) -or $actualVersion -lt $minimumVersion) {
          $failures.Add("requires '$fileName' version $minimumVersion or later; '$systemFile' reports '$fileVersion'")
        }
      }
    }
  }
  $executable = $null
  if ($Operation.PrerequisiteProgramFilesExecutable) {
    $relative = [string]$Operation.PrerequisiteProgramFilesExecutable
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $relative -match '["\r\n:*?]') { throw 'Invalid package prerequisite executable path.' }
    $executable = Join-Path $env:ProgramFiles $relative
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { $failures.Add("requires $($Operation.PrerequisitePackageId) at '$executable'") }
  }
  if ($Operation.PrerequisitePowerShellModuleName) {
    $moduleName = [string]$Operation.PrerequisitePowerShellModuleName
    $moduleDirectoryName = [string]$Operation.PrerequisiteModuleDirectory
    if ($moduleName -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$' -or
        $moduleDirectoryName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw 'Invalid PowerShell module prerequisite identity.' }
    $toolsDirectory = (Get-RidePackageConfiguration -Scope Machine).ToolsDirectory
    $prerequisiteDirectory = Join-Path $toolsDirectory $moduleDirectoryName
    $manifestPath = Join-Path $prerequisiteDirectory ($moduleName + '.psd1')
    $modulePackage = @{ PackageId = $moduleDirectoryName; SelectedVariant = 'portable'; ResolvedToolsDirectory = $toolsDirectory; InstallDirectory = $prerequisiteDirectory }
    $modulePackageState = Get-RidePortableState -Operation $modulePackage
    if (-not $modulePackageState.Present -or -not $modulePackageState.Healthy) {
      $failures.Add("requires the healthy RIDE-managed PowerShell module package '$moduleDirectoryName'")
    } elseif (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
      $failures.Add("requires PowerShell module '$moduleName' version $($Operation.PrerequisitePowerShellModuleMinimumVersion) in '$prerequisiteDirectory'")
    } else {
      try { $moduleManifest = Import-PowerShellDataFile -LiteralPath $manifestPath -ErrorAction Stop }
      catch { $failures.Add("cannot read PowerShell module manifest '$manifestPath': $($_.Exception.Message)"); $moduleManifest = $null }
      if ($moduleManifest) {
        [version]$requiredModuleVersion = [version]::MinValue
        [version]$actualModuleVersion = [version]::MinValue
        if (-not [version]::TryParse([string]$Operation.PrerequisitePowerShellModuleMinimumVersion, [ref]$requiredModuleVersion) -or
            -not [version]::TryParse([string]$moduleManifest.ModuleVersion, [ref]$actualModuleVersion) -or
            $actualModuleVersion -lt $requiredModuleVersion) {
          $failures.Add("requires PowerShell module '$moduleName' version $($Operation.PrerequisitePowerShellModuleMinimumVersion) or later; manifest reports '$($moduleManifest.ModuleVersion)'")
        }
      }
    }
  }
  [pscustomobject]@{
    Satisfied = ($failures.Count -eq 0)
    Reason = if ($failures.Count) { "$($Operation.Id) " + ($failures -join '; ') } else { $null }
    Executable = $executable
    Directory = if ($executable) { Split-Path -Parent $executable } elseif ($prerequisiteDirectory) { $prerequisiteDirectory } else { $null }
  }
}

function Test-RideDotNetFramework35Installed {
  $keyPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5'
  try {
    $value = Get-ItemProperty -LiteralPath $keyPath -Name Install -ErrorAction Stop
    return ([int]$value.Install -eq 1)
  } catch {
    if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $false }
    throw "Could not inspect the installed .NET Framework 3.5 runtime: $($_.Exception.Message)"
  }
}

function Get-RidePackagePrerequisiteDirectory {
  param([hashtable] $Operation)
  $status = Get-RidePackagePrerequisiteStatus -Operation $Operation
  if (-not $status.Satisfied) {
    if ($Operation.PrerequisitePackageId) { throw "$($status.Reason). Install or update the declared prerequisite first and remove it last." }
    throw "$($status.Reason). Install the documented shared runtime first."
  }
  $status.Directory
}

function Test-RidePackageAdministrator {
  ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-RidePackageExecutionContext {
  param([hashtable] $Operation)
  if ($Operation.RequiresUnelevatedUser -and (Test-RidePackageAdministrator)) { throw 'This current-user installer requires a non-elevated PowerShell session.' }
}

function Invoke-RidePackageInstallerProcess {
  param([hashtable] $Operation, [string] $FilePath, [string] $ArgumentList,
    [ValidateSet('ProcessTree','Process')][string]$WaitMode='ProcessTree')
  Assert-RidePackageExecutionContext -Operation $Operation
  $prerequisiteDirectory = Get-RidePackagePrerequisiteDirectory -Operation $Operation
  $originalPath = $env:PATH
  try {
    # Newly installed Git is not yet in this process's inherited PATH.
    if ($prerequisiteDirectory) { $env:PATH = $prerequisiteDirectory + ';' + $originalPath }
    if($WaitMode -eq 'Process'){
      $process=Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WindowStyle Hidden -PassThru
      # Retain the handle for Windows PowerShell 5.1 exit-code reporting. The
      # reviewed installer may launch the application after completing setup.
      $null=$process.Handle
      $process.WaitForExit()
      $process.Refresh()
      if($null -eq $process.ExitCode){throw 'Installer process exit code is unavailable.'}
      $process
    }else{
      Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WindowStyle Hidden -Wait -PassThru
    }
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
    staging. Declared EXE InstallerWaitMode Process waits for the installer itself;
    the default ProcessTree also waits for descendants. Exit-code and presence
    checks remain required. Uninstall completion is unchanged.
    ZIP supports one self-contained installer. Use the engine for privilege, preview,
    and snapshot capture.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER CacheDirectory
    Versioned artifact cache root selected by the engine for the operation scope.

  .PARAMETER OfflineArtifact
    Engine-verified, read-leased local portable artifact. Explicit null/invalid
    records fail; acquisition and certificate network checks are never substituted.

  .PARAMETER GitHubAuthentication
    Anonymous (default) or explicit PAT for GitHub release discovery only.

  .PARAMETER GitHubCredentialReference
    Nonsecret enrolled reference required with PAT. Resolved only during acquisition.

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
    [Parameter(Mandatory = $true)][string] $CacheDirectory,
    [ValidateSet('Anonymous','PAT')][string] $GitHubAuthentication = 'Anonymous',
    [string] $GitHubCredentialReference,
    $OfflineArtifact
  )

  $Operation = Resolve-RidePackageSelection -Operation $Operation
  $offline = $PSBoundParameters.ContainsKey('OfflineArtifact')
  if ($offline -and ($null -eq $OfflineArtifact -or $OfflineArtifact.Offline -ne $true -or
      $OfflineArtifact.Sha256 -notmatch '^[a-fA-F0-9]{64}$' -or -not $OfflineArtifact.Version -or
      $OfflineArtifact.OfflineCapability -cne 'DeclaredNoNetwork' -or $OfflineArtifact.InstallerType -cne $Operation.InstallerType -or
      $Operation.InstallerType -notin @('Portable', 'Exe', 'Msi') -or $Operation.PrerequisitePackageId -or $Operation.DependsOn -or
      $GitHubAuthentication -ne 'Anonymous' -or $GitHubCredentialReference)) { throw 'Invalid or unsupported offline package; no network fallback is allowed.' }
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
  $download = if ($offline) { $OfflineArtifact } else { Save-RidePackageArtifact -Operation $Operation -DestinationDirectory $CacheDirectory -GitHubAuthentication $GitHubAuthentication -GitHubCredentialReference $GitHubCredentialReference }
  if ($download.Sha256 -and (Get-FileHash -LiteralPath $download.Path -Algorithm SHA256).Hash -ne $download.Sha256) { throw 'Retained artifact SHA-256 changed before installation.' }
  if ($Operation.InstallerType -eq 'Portable') { Install-RidePortablePayload -Operation $Operation -Artifact $download -Offline:$offline; return $download }
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
  $configurationStaging = $null
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
    if ($Operation.InstallerConfiguration) {
      $configurationStaging = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-PackageConfig-' + [guid]::NewGuid().ToString('N'))
      $configurationStaging = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($configurationStaging)
      $null = [IO.Directory]::CreateDirectory($configurationStaging)
      if ((Get-Item -LiteralPath $configurationStaging).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installer configuration staging cannot use reparse points.' }
      $configurationPath = Join-Path $configurationStaging 'installer.ini'
      $configurationSection = [string]$Operation.InstallerConfigurationSection
      if (-not $configurationSection -or $configurationSection -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw 'Installer configuration requires a valid declared section name.' }
      $configurationLines = @("[$configurationSection]") + @(foreach ($key in @($Operation.InstallerConfiguration.Keys | Sort-Object -CaseSensitive)) {
        $value = if ($Operation.InstallerConfiguration[$key]) { 'true' } else { 'false' }
        "$key=$value"
      })
      $configurationBytes = [Text.Encoding]::ASCII.GetBytes(($configurationLines -join "`r`n") + "`r`n")
      $configurationStream = [IO.File]::Open($configurationPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $configurationStream.Write($configurationBytes, 0, $configurationBytes.Length) } finally { $configurationStream.Dispose() }
      if (-not $Operation.InstallerArguments.Contains('{InstallerConfigurationPath}')) { throw 'Installer configuration requires an explicit path token in InstallerArguments.' }
      $installerArguments = $installerArguments.Replace('{InstallerConfigurationPath}', $configurationPath)
    }
    $waitMode=if($Operation.ContainsKey('InstallerWaitMode')){[string]$Operation.InstallerWaitMode}else{'ProcessTree'}
    $process = if ($Operation.PreserveRoamingDirectoryOnInstall) {
      Invoke-RidePreservingPackageOperation -Operation $Operation -FilePath $installerExe -ArgumentList $installerArguments -WaitMode $waitMode
    } else {
      Invoke-RidePackageInstallerProcess -Operation $Operation -FilePath $installerExe -ArgumentList $installerArguments -WaitMode $waitMode
    }
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
    if ($configurationStaging -and [IO.Directory]::Exists($configurationStaging)) {
      $resolvedConfigurationStaging = (Get-Item -LiteralPath $configurationStaging).FullName
      if ($resolvedConfigurationStaging -ne [IO.Path]::GetFullPath($configurationStaging) -or (Split-Path -Leaf $resolvedConfigurationStaging) -notmatch '^RIDE-PackageConfig-[0-9a-f]{32}$') { throw 'Unexpected installer configuration staging directory.' }
      Remove-Item -LiteralPath $resolvedConfigurationStaging -Recurse -Force
    }
  }
  $download
}

function Get-RideRoamingApplicationDataRoot {
  [Environment]::GetFolderPath('ApplicationData')
}

function Invoke-RidePreservingPackageOperation {
  param([hashtable] $Operation, [string] $FilePath, [string] $ArgumentList,
    [ValidateSet('ProcessTree','Process')][string]$WaitMode='ProcessTree')
  if (-not $Operation.PreserveRoamingDirectory) { return Invoke-RidePackageInstallerProcess -Operation $Operation -FilePath $FilePath -ArgumentList $ArgumentList -WaitMode $WaitMode }
  $name=[string]$Operation.PreserveRoamingDirectory
  $processNames = if ($Operation.PreservationProcessNames) { @($Operation.PreservationProcessNames) } elseif ($Operation.PreservationProcessName) { @($Operation.PreservationProcessName) } else { @() }
  if ($Operation.Scope -ne 'User' -or $Operation.InstallerType -ne 'Exe' -or $name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,79}$' -or $name.EndsWith('.') -or $name.EndsWith(' ') -or $name -match '^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)' -or $processNames.Count -lt 1 -or @($processNames | Where-Object { $_ -notmatch '^[a-zA-Z0-9_-]+$' }).Count -gt 0 -or ($Operation.PreservationProcessNames -and $Operation.PreservationProcessName)) { throw 'Invalid user-data preservation directory.' }
  foreach ($processName in $processNames) {
    if (Get-Process -Name $processName -ErrorAction SilentlyContinue) { throw "Close $processName before changing $($Operation.Name); user data was not moved." }
  }
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
    Invoke-RidePackageInstallerProcess -Operation $Operation -FilePath $FilePath -ArgumentList $ArgumentList -WaitMode $WaitMode
  }
  finally {
    if ($moved) {
      if (Test-Path -LiteralPath $original) {
        $conflictingData = Get-Item -LiteralPath $original -Force -ErrorAction Stop
        if (-not $conflictingData.PSIsContainer -or ($conflictingData.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "User-data restoration has a non-directory collision. Preserved data remains at '$holding'; original destination is '$original'." }
        $createdData = Join-Path $root ('.'+$name+'.ride-created-'+[guid]::NewGuid().ToString('N'))
        try { Move-Item -LiteralPath $original -Destination $createdData -ErrorAction Stop }
        catch { throw "Could not retain installer-created user data. Original data remains at '$holding'; new data remains at '$original'. $($_.Exception.Message)" }
      }
      try { Move-Item -LiteralPath $holding -Destination $original -ErrorAction Stop }
      catch { throw "User-data restoration failed. Preserved data remains at '$holding'; original destination is '$original'. $($_.Exception.Message)" }
      if ($createdData) { Write-Warning "The package created a new user-data directory during install/removal; it was retained at '$createdData' while the original data was restored." }
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
    A declared user-data preservation contract refuses running processes and temporarily renames
    its Roaming data directory, restoring it after the installer or uninstaller finishes or fails.
    Newly created data is retained separately if the original path collides. Interrupted restoration
    retains the directory and journal for review instead of overwriting.
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
  $process = Invoke-RidePreservingPackageOperation -Operation $Operation -FilePath $exe -ArgumentList $arguments
  $successExitCodes = if ($Operation.SuccessExitCodes) { @($Operation.SuccessExitCodes) } else { @(0) }
  if ($process.ExitCode -notin $successExitCodes) { throw "Uninstaller for $($Operation.Name) exited with code $($process.ExitCode)." }
  if ($process.ExitCode -eq 3010) { Write-Warning "$($Operation.Name) removal succeeded; a restart is required." }
  if ((Get-RideInstalledPackage -Operation $Operation).Present) { throw "Uninstaller completed but $($Operation.Name) is still detected." }
}

Export-ModuleMember -Function Get-RideInstalledPackage, Get-RidePackagePrerequisiteStatus, Resolve-RidePackageArtifact, Save-RidePackageArtifact, Install-RidePackage, Uninstall-RidePackage
