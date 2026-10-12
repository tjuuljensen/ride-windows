<#
.SYNOPSIS
  Resolve official desktop application feeds into exact versioned artifacts.
.DESCRIPTION
  Reads publisher metadata without downloading or executing application payloads.
  Rejects ambiguous artifacts and URLs outside declared publisher hosts.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Owner: RIDE-Windows maintainers. Version: 0.3.0.
  Changelog: 0.3.0: Resolve pinned WinSCP portable pages with publisher SHA-256.
    0.2.0: Bind Signal SHA-512 and resolve explicit Mozilla locale/architecture.
    0.1.0: Add VS Code, Mozilla and explicit publisher-link resolution.
#>

function Get-RidePublisherChecksum {
  param([string] $Uri, [string] $Member)
  $page = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
  $content = if ($page.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($page.Content) } else { [string]$page.Content }
  if ($content.Length -gt 1048576) { throw 'Publisher checksum file exceeds 1 MiB.' }
  $pattern = '(?im)^(?<digest>[a-f0-9]{64})[ \t]+\*?' + [regex]::Escape($Member) + '\r?$'
  $matches = @([regex]::Matches($content, $pattern))
  if ($matches.Count -ne 1) { throw 'Publisher checksum must identify exactly one selected artifact.' }
  'sha256:' + $matches[0].Groups['digest'].Value.ToLowerInvariant()
}

function Resolve-RidePublisherArtifact {
  <#
  .SYNOPSIS
    Resolve an official feed to one versioned artifact.
  .PARAMETER Operation
    Package metadata with a supported provider and publisher host constraints.
  .EXAMPLE
    Resolve-RidePublisherArtifact -Operation $package
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Exact version, URL and digest.
  .NOTES
    No payload is executed. Version follows the module overview.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation)
  $source = [uri]$Operation.DownloadUri
  if (-not $source.IsAbsoluteUri -or $source.Scheme -ne 'https' -or -not $source.IsDefaultPort -or $source.UserInfo -or $source.Fragment) { throw 'Publisher metadata must use HTTPS without credentials or fragments.' }
  $digest = $null
  $publisherSha256 = $null; $publisherChecksumUri = $null
  $checksumUris = @(); $signatureUris = @()
  switch ($Operation.DownloadProvider) {
    'WinSCPPortablePage' {
      $version = [string]$Operation.PackageVersion
      if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'WinSCP requires an explicit stable release version.' }
      $name = "WinSCP-$version-Portable.zip"
      if ($source.AbsoluteUri -cne "https://winscp.net/download/$name/download" -or
          $Operation.Architecture -ne 'x86' -or $Operation.InstallerType -ne 'Portable' -or
          $Operation.PortableFormat -ne 'Zip') { throw 'Invalid WinSCP portable publisher source or distribution.' }
      $page = Invoke-WebRequest -Uri $source -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
      $content = if ($page.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($page.Content) } else { [string]$page.Content }
      if ($content.Length -gt 1048576) { throw 'WinSCP publisher page exceeds 1 MiB.' }
      $hashes = @([regex]::Matches($content, '(?i)<li>\s*SHA-256:\s*([a-f0-9]{64})\s*</li>'))
      if ($hashes.Count -ne 1) { throw 'WinSCP page must identify exactly one publisher SHA-256.' }
      $digest = 'sha256:' + $hashes[0].Groups[1].Value.ToLowerInvariant()
      $publisherSha256 = $hashes[0].Groups[1].Value.ToLowerInvariant()
      $publisherChecksumUri = $source.AbsoluteUri
      # The versioned page is durable. Resolve its public, temporary CDN link
      # for this acquisition; never store an expiring URL as a catalog source.
      $links = @($page.Links | ForEach-Object { [Net.WebUtility]::HtmlDecode([string]$_.href) } |
        Where-Object { $_ -match ('^https://cdn\.winscp\.net/files/' + [regex]::Escape($name) + '\?') } | Sort-Object -Unique)
      if ($links.Count -ne 1) { throw 'WinSCP page must identify exactly one selected CDN artifact.' }
      $uri = $links[0]
      $cdn = [uri]$uri
      if ($cdn.AbsolutePath -cne "/files/$name" -or $cdn.Query -notmatch '^\?secure=[A-Za-z0-9_-]{22}==,[0-9]{10}$' -or
          $cdn.UserInfo -or $cdn.Fragment -or -not $cdn.IsDefaultPort) { throw 'Invalid WinSCP publisher CDN link.' }
      $checksumUris = @($source.AbsoluteUri)
    }
    'SignalDesktopFeed' {
      if ($source.Host -ne 'updates.signal.org' -or $source.AbsolutePath -ne '/desktop/latest.yml' -or
          $source.Query -or $Operation.Architecture -ne 'x64') { throw 'Invalid Signal x64 update source.' }
      $page = Invoke-WebRequest -Uri $source -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
      $content = if ($page.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($page.Content) } else { [string]$page.Content }
      if ($content.Length -gt 131072) { throw 'Signal update feed exceeds 128 KiB.' }
      # Read only the declared scalar format; no general YAML evaluation.
      $versions = @([regex]::Matches($content, '(?m)^version: ([0-9]+\.[0-9]+\.[0-9]+)[ \t]*\r?$'))
      $paths = @([regex]::Matches($content, '(?m)^path: (signal-desktop-win-x64-[0-9]+\.[0-9]+\.[0-9]+\.exe)[ \t]*\r?$'))
      $hashes = @([regex]::Matches($content, '(?m)^sha512: ([A-Za-z0-9+/]{86}==)[ \t]*\r?$'))
      if ($versions.Count -ne 1 -or $paths.Count -ne 1 -or $hashes.Count -ne 1) { throw 'Signal feed must identify one stable x64 release and SHA-512.' }
      $version = $versions[0].Groups[1].Value; $name = $paths[0].Groups[1].Value
      if ($name -cne "signal-desktop-win-x64-$version.exe") { throw 'Signal version and artifact filename disagree.' }
      $entries = @([regex]::Matches($content, '(?m)^  - url: ' + [regex]::Escape($name) + '[ \t]*\r?\n    sha512: ([A-Za-z0-9+/]{86}==)[ \t]*\r?$'))
      if ($entries.Count -ne 1 -or $entries[0].Groups[1].Value -cne $hashes[0].Groups[1].Value) { throw 'Signal file entry and release SHA-512 disagree.' }
      $bytes = [Convert]::FromBase64String($hashes[0].Groups[1].Value)
      if ($bytes.Length -ne 64 -or [Convert]::ToBase64String($bytes) -cne $hashes[0].Groups[1].Value) { throw 'Invalid Signal SHA-512 encoding.' }
      $digest = 'sha512:' + ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
      $uri = 'https://updates.signal.org/desktop/' + $name
      $checksumUris = @($source.AbsoluteUri)
    }
    'VSCodeUpdateApi' {
      if ($source.Host -ne 'update.code.visualstudio.com' -or $source.AbsolutePath -ne '/api/update/win32-x64-user/stable/latest') { throw 'Invalid VS Code user update source.' }
      $feed = Invoke-RestMethod -Uri $source -TimeoutSec 120 -ErrorAction Stop
      $version = [string]$feed.productVersion; $uri = [string]$feed.url
      if ($feed.sha256hash -notmatch '^[a-fA-F0-9]{64}$') { throw 'VS Code feed is missing its SHA-256.' }
      $digest = 'sha256:' + $feed.sha256hash
      $name = "VSCodeUserSetup-x64-$version.exe"
    }
    'MozillaVersionsJson' {
      if ($source.Host -ne 'product-details.mozilla.org' -or $Operation.MozillaProduct -notin @('firefox', 'thunderbird') -or
          $source.AbsolutePath -ne "/1.0/$($Operation.MozillaProduct)_versions.json") { throw 'Invalid Mozilla version source.' }
      $feed = Invoke-RestMethod -Uri $source -TimeoutSec 120 -ErrorAction Stop
      $version = [string]$feed.($Operation.VersionKey)
      if ($version -notmatch '^\d+(?:\.\d+)+(?:esr)?$') { throw 'Unsafe publisher version.' }
      $locale = if ($Operation.ContainsKey('MozillaLocale')) { [string]$Operation.MozillaLocale } else { 'en-US' }
      if ($locale -notmatch '^[a-z]{2,3}(?:-[a-zA-Z0-9]{2,8})*$') { throw 'Unsafe Mozilla locale.' }
      $platform = if (-not $Operation.Architecture -or $Operation.Architecture -eq 'x64') { 'win64' } elseif ($Operation.Architecture -eq 'x86') { 'win' } else { throw 'Unsupported Mozilla architecture.' }
      $product = if ($Operation.MozillaProduct -eq 'firefox') { 'Firefox' } else { 'Thunderbird' }
      $name = "$product Setup $version.$(([string]$Operation.InstallerType).ToLowerInvariant())"
      $member = "$platform/$locale/$name"
      $uri = "https://archive.mozilla.org/pub/$($Operation.MozillaProduct)/releases/$version/" + "$platform/$locale/" + [uri]::EscapeDataString($name)
      $releaseUri = "https://archive.mozilla.org/pub/$($Operation.MozillaProduct)/releases/$version/"
      $checksumUris = @($releaseUri + 'SHA256SUMS')
      $digest = Get-RidePublisherChecksum -Uri $checksumUris[0] -Member $member
      $directory = Invoke-WebRequest -Uri $releaseUri -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
      $signatureUris = @($directory.Links | Where-Object { $_.href -match '(^|/)SHA256SUMS\.asc$' } | ForEach-Object { ([uri]::new([uri]$releaseUri, [string]$_.href)).AbsoluteUri } | Where-Object { $_ -eq ($releaseUri + 'SHA256SUMS.asc') } | Sort-Object -Unique)
    }
    'PublisherLinkPage' {
      $page = Invoke-WebRequest -Uri $source -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
      $links = @($page.Links | ForEach-Object { [string]$_.href } | Where-Object { $_ -match $Operation.AssetPattern } | Sort-Object -Unique)
      if ($links.Count -ne 1) { throw "Expected one publisher artifact; found $($links.Count)." }
      $uri = ([uri]::new($source, $links[0])).AbsoluteUri
      if ($Operation.PageVersionPattern) {
        $pageMatch = [regex]::Match([string]$page.Content, [string]$Operation.PageVersionPattern)
        if (-not $pageMatch.Success) { throw 'Publisher page does not identify its current version.' }
        $pageVersion = $pageMatch.Groups['version'].Value
        if ($pageVersion -notmatch '^\d+(?:\.\d+)+$') { throw 'Unsafe publisher page version.' }
        $uri = $uri.Replace('/latest/', '/' + $pageVersion + '/')
      }
      $match = [regex]::Match($uri, [string]$Operation.VersionPattern)
      if (-not $match.Success -or -not $match.Groups['version'].Success) { throw 'Publisher artifact URL does not identify a version.' }
      $version = $match.Groups['version'].Value
      $name = [uri]::UnescapeDataString([IO.Path]::GetFileName(([uri]$uri).AbsolutePath))
      if ($Operation.ChecksumAssetPattern) {
        $checksumLinks = @($page.Links | ForEach-Object { [string]$_.href } | Where-Object { $_ -match $Operation.ChecksumAssetPattern } | Sort-Object -Unique)
        if ($checksumLinks.Count -ne 1) { throw 'Publisher page must identify exactly one checksum file.' }
        $checksumUri = ([uri]::new($source, $checksumLinks[0])).AbsoluteUri.Replace('/latest/', '/' + $version + '/')
        $parsedChecksum = [uri]$checksumUri
        if ($parsedChecksum.Scheme -ne 'https' -or -not $parsedChecksum.IsDefaultPort -or $parsedChecksum.UserInfo -or $parsedChecksum.Fragment -or $parsedChecksum.Host -notin $Operation.AllowedDownloadHosts) { throw 'Checksum URL is outside declared publisher HTTPS hosting.' }
        $checksumUris = @($checksumUri)
        $digest = Get-RidePublisherChecksum -Uri $checksumUri -Member $Operation.ChecksumMember
      }
      $signatureCandidates = @(($uri + '.gpg'), ($uri + '.asc'), ($uri + '.sig')) + @($checksumUris | ForEach-Object { $_ + '.gpg'; $_ + '.asc' })
      $signatureUris = @($page.Links | Where-Object { $_.href -match '\.(gpg|asc|sig)$' } | ForEach-Object { ([uri]::new($source, [string]$_.href)).AbsoluteUri.Replace('/latest/', '/' + $version + '/') } | Where-Object { $_ -in $signatureCandidates } | Sort-Object -Unique)
    }
    default { throw "Unsupported publisher provider: $($Operation.DownloadProvider)" }
  }
  if ($version -notmatch '^\d+(?:\.\d+)+(?:esr)?$' -or $name -match '[\\/\x00-\x1f:"*?<>|]' -or [IO.Path]::GetFileName($name) -ne $name) { throw 'Unsafe publisher version or artifact filename.' }
  $resolved = [uri]$uri
  if (-not $resolved.IsAbsoluteUri -or $resolved.Scheme -ne 'https' -or -not $resolved.IsDefaultPort -or $resolved.UserInfo -or $resolved.Fragment -or $resolved.Host -notin $Operation.AllowedDownloadHosts) { throw 'Artifact URL is outside declared publisher HTTPS hosting.' }
  [pscustomobject]@{ PackageId = $Operation.PackageId; Version = $version; Architecture = $Operation.Architecture; FileName = $name; Uri = $uri; OriginUri = $Operation.ProductUri; SourceUri = $Operation.DownloadUri; ProviderDigest = $digest; PublisherSha256 = $publisherSha256; PublisherChecksumUri = $publisherChecksumUri; ChecksumUris = $checksumUris; SignatureUris = $signatureUris }
}

Export-ModuleMember -Function Resolve-RidePublisherArtifact
