<#
.SYNOPSIS
  Acquire selected JoeWare ZIP files from their current publisher pages.
.DESCRIPTION
  Reads the frozen 41-product review inventory, resolves each selected product
  page at invocation time, and submits its publisher download form. Saves ZIP
  bytes and a local SHA-256/member observation into a new destination folder.
  This tool does not extract, install, execute, or configure any downloaded file.
.PARAMETER Product
  One or more product names from the reviewed JoeWare collection. Omit to
  acquire all 41 reviewed products.
.PARAMETER DestinationDirectory
  New or empty directory in which to retain downloaded ZIP files and evidence.
.EXAMPLE
  .\tools\Download-JoeWareCollection.ps1 -Product rdp-sec-check -DestinationDirectory .\artifacts\joeware
.EXAMPLE
  .\tools\Download-JoeWareCollection.ps1 -DestinationDirectory D:\staging\joeware -WhatIf
.INPUTS
  None.
.OUTPUTS
  System.Management.Automation.PSCustomObject. Per-product source, version,
  archive hash, and member-list evidence.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: network access to the official JoeWare HTTPS pages; an empty
  or new destination directory; the repository's reviewed 41-product inventory.
  Side effects: submits the publisher's optional-email download form and writes
  ZIP files and a JSON observation manifest. It never extracts or runs payloads.
  Recovery: remove only the newly created output directory after reviewing and
  preserving any desired artifacts/evidence. Existing nonempty destinations are
  refused. Publisher MD5/SHA-1 values are observations, not SHA-256 verification.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add bounded current-page ZIP acquisition and archive identity capture.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string[]] $Product,
  [Parameter(Mandatory)][string] $DestinationDirectory
)

$ErrorActionPreference = 'Stop'

function Assert-JoeWareHttpsUri {
  param([Parameter(Mandatory)][string] $Uri)
  $parsed = [uri]$Uri
  if (-not $parsed.IsAbsoluteUri -or $parsed.Scheme -cne 'https' -or
      -not $parsed.IsDefaultPort -or $parsed.UserInfo -or $parsed.Fragment -or
      $parsed.Host -notin @('www.joeware.net', 'joeware.net')) {
    throw "JoeWare returned a URL outside its official HTTPS origin: $Uri"
  }
  $parsed
}

function Get-JoeWarePageVersion {
  param([Parameter(Mandatory)][string] $Html)
  if ($Html.Length -gt 2097152) { throw 'JoeWare product page exceeds 2 MiB.' }
  $section = [regex]::Match($Html, '(?is)Current\s+Version(?<tail>.{0,512}?)(?=Version\s+History|Modification\(s\)|</body>|$)')
  if (-not $section.Success) { throw 'The JoeWare product page did not expose a current-version section.' }
  $label = [Net.WebUtility]::HtmlDecode(([regex]::Replace($section.Groups['tail'].Value, '<[^>]*>', ' ')) -replace '\s+', ' ').Trim()
  $versionMatch = [regex]::Match($label, '(?i)\bVersion\s+(?<version>[0-9]+(?:\.[0-9A-Za-z-]+)+)')
  if (-not $versionMatch.Success) { $versionMatch = [regex]::Match($label, '(?<version>[0-9]+(?:\.[0-9A-Za-z-]+)+)') }
  if (-not $versionMatch.Success) { throw 'The JoeWare product page did not expose one parseable current version.' }
  [pscustomobject]@{ Version = $versionMatch.Groups['version'].Value; Label = $label }
}

function Get-JoeWareVersionList {
  $uri = 'https://www.joeware.net/freetools/versions.txt'
  $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
  $text = [string]$response.Content
  if ($text.Length -gt 1048576) { throw 'JoeWare versions.txt exceeds 1 MiB.' }
  $rows = @{}
  foreach ($line in ($text -split "`r?`n")) {
    if ($line -match '^(?<name>[A-Za-z0-9-]+),(?<version>[^,]+),(?<date>[^,]+),(?<md5>[a-fA-F0-9]{32})?,(?<sha1>[a-fA-F0-9]{40})?$') {
      $rows[$matches.name.ToLowerInvariant()] = [pscustomobject]@{
        Version = $matches.version; Date = $matches.date
        Md5 = $matches.md5; Sha1 = $matches.sha1
      }
    }
  }
  [pscustomobject]@{ Uri = $uri; Sha256 = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($text))) -Algorithm SHA256).Hash.ToLowerInvariant(); Rows = $rows }
}

function Get-JoeWareProductForm {
  param([Parameter(Mandatory)][pscustomobject] $Member)
  $pageUri = Assert-JoeWareHttpsUri -Uri ([string]$Member.ProductUri)
  $page = Invoke-WebRequest -Uri $pageUri.AbsoluteUri -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
  $html = [string]$page.Content
  $pageVersion = Get-JoeWarePageVersion -Html $html
  $fields = @($page.InputFields)
  $downloadFields = @($fields | Where-Object { [string]$_.name -ceq 'download' })
  $buttonFields = @($fields | Where-Object { [string]$_.name -ceq 'B1' })
  if ($downloadFields.Count -ne 1 -or $buttonFields.Count -ne 1) { throw "Expected one current publisher download form for '$($Member.Name)' on $($Member.ProductUri)." }
  $fileName = [string]$downloadFields[0].value
  if ($fileName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.zip$') { throw "Publisher returned an unsafe ZIP name for '$($Member.Name)'." }
  [pscustomobject]@{
    Name = [string]$Member.Name
    PageUri = $pageUri.AbsoluteUri
    Version = $pageVersion.Version
    VersionLabel = $pageVersion.Label
    FileName = $fileName
    DownloadFormValue = [string]$downloadFields[0].value
    ButtonValue = [string]$buttonFields[0].value
    FormUri = 'https://www.joeware.net/downloads/dl2.php'
    PageSha256 = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($html))) -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}

function Get-JoeWareZipObservation {
  param(
    [Parameter(Mandatory)][string] $Path,
    [Parameter(Mandatory)][string] $ProductName,
    [Parameter(Mandatory)][string] $Version,
    [Parameter(Mandatory)][string] $VersionLabel,
    [Parameter(Mandatory)][string] $PageUri,
    [Parameter(Mandatory)][object] $VersionList
  )
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($Path)
  try {
    if (-not $zip.Entries.Count -or $zip.Entries.Count -gt 10000) { throw "Archive '$Path' has an empty or oversized member list." }
    $names = @(); $seen = @{}; $archiveVersions = @{}; $textBytesRemaining = 2097152
    foreach ($entry in $zip.Entries) {
      $name = [string]$entry.FullName
      if (-not $name -or $name.Length -gt 240 -or $name -match '[\\\x00-\x1f:]|^/|(^|/)\.{1,2}(/|$)|//|(^|/)\.(?:ride|git)(?:/|$)' -or $seen.ContainsKey($name)) {
        throw "Archive '$Path' contains an unsafe or duplicate member path."
      }
      $seen[$name] = $true
      $names += $name
      if (-not $entry.FullName.EndsWith('/') -and $entry.Length -le 262144 -and $entry.Length -le $textBytesRemaining -and
          [IO.Path]::GetExtension($name) -in @('.txt','.pl','.pm','.md','.ini','.cfg','.html','.htm')) {
        $textBytesRemaining -= [long]$entry.Length
        $memberStream = $entry.Open()
        try {
          $reader = [IO.StreamReader]::new($memberStream, [Text.Encoding]::UTF8, $true, 4096, $true)
          try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $memberStream.Dispose() }
        foreach ($match in [regex]::Matches($text, '(?i)(?:joeware(?:\.net)?\s+V|version\s+)(?<version>[0-9]+(?:\.[0-9A-Za-z-]+)+)')) {
          $archiveVersions[$match.Groups['version'].Value] = $true
        }
      }
    }
  } finally { $zip.Dispose() }
  $listRow = $VersionList.Rows[[string]$ProductName.ToLowerInvariant()]
  $versionDifference = if ($listRow -and $listRow.Version -cne $Version) {
    [pscustomobject]@{ PageVersion = $Version; VersionListVersion = $listRow.Version; VersionListDate = $listRow.Date }
  } else { $null }
  $archiveVersionCandidates = @($archiveVersions.Keys | Sort-Object -CaseSensitive)
  $archiveVersionDifference = @($archiveVersionCandidates | Where-Object { $_ -cne $Version })
  [pscustomobject]@{
    Product = $ProductName
    PageVersion = $Version
    PageVersionLabel = $VersionLabel
    ProductPageUri = $PageUri
    FileName = [IO.Path]::GetFileName($Path)
    Length = (Get-Item -LiteralPath $Path).Length
    Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    Members = @($names | Sort-Object -CaseSensitive)
    VersionListObservation = if ($listRow) { [pscustomobject]@{ Version = $listRow.Version; Date = $listRow.Date; Md5 = $listRow.Md5; Sha1 = $listRow.Sha1 } } else { $null }
    PageVersionDiscrepancy = $versionDifference
    ArchiveVersionCandidates = $archiveVersionCandidates
    ArchiveVersionDifference = $archiveVersionDifference
    ArchiveVersionInspection = 'Version strings are inert text observations only; they require review before assigning archive identity.'
  }
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$inventoryPath = Join-Path $repoRoot 'docs/archive/evidence/joeware-collection-inventory-2026-10-17.json'
if (-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) { throw 'The reviewed JoeWare product inventory is unavailable.' }
$inventory = Get-Content -LiteralPath $inventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($inventory.MemberCount -ne 41 -or @($inventory.Members).Count -ne 41) { throw 'The reviewed JoeWare inventory does not contain exactly 41 products.' }
$members = @($inventory.Members)
if ($Product) {
  $requested = @($Product | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)
  $unknown = @($requested | Where-Object { $_ -notin @($members.Name) })
  if ($unknown.Count) { throw "Unknown JoeWare product selection: $($unknown -join ', ')" }
  $members = @($members | Where-Object { $_.Name -in $requested })
  if (-not $members.Count) { throw 'Select at least one reviewed JoeWare product.' }
}

if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($DestinationDirectory)) { throw 'DestinationDirectory must not contain wildcard characters.' }
$destination = [IO.Path]::GetFullPath($DestinationDirectory)
if (Test-Path -LiteralPath $destination) {
  if (@(Get-ChildItem -LiteralPath $destination -Force).Count) { throw 'DestinationDirectory must be new or empty.' }
} elseif ($PSCmdlet.ShouldProcess($destination, 'Create JoeWare acquisition directory')) {
  New-Item -ItemType Directory -Path $destination -Force:$false | Out-Null
}

$versionList = Get-JoeWareVersionList
$forms = @($members | ForEach-Object { Get-JoeWareProductForm -Member $_ })
$observations = @()
foreach ($form in $forms) {
  $target = Join-Path $destination $form.FileName
  if (Test-Path -LiteralPath $target) { throw "Refusing to overwrite existing archive: $target" }
  if (-not $PSCmdlet.ShouldProcess($target, "Download latest JoeWare $($form.Name) ZIP ($($form.Version))")) { continue }
  $temporary = Join-Path $destination ('.' + $form.FileName + '.' + [guid]::NewGuid().ToString('N') + '.download')
  try {
    $body = @{ download = $form.DownloadFormValue; email = ''; B1 = $form.ButtonValue }
    $response = Invoke-WebRequest -Uri $form.FormUri -Method Post -Body $body -UseBasicParsing -TimeoutSec 600 -OutFile $temporary -PassThru -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $temporary -PathType Leaf) -or (Get-Item -LiteralPath $temporary).Length -lt 22) { throw "Publisher returned an empty download for '$($form.Name)'." }
    $finalUri = [string]$response.BaseResponse.ResponseUri.AbsoluteUri
    $null = Assert-JoeWareHttpsUri -Uri $finalUri
    $stream = [IO.File]::OpenRead($temporary)
    try {
      $signature = New-Object byte[] 4
      if ($stream.Read($signature, 0, 4) -ne 4 -or $signature[0] -ne 0x50 -or $signature[1] -ne 0x4b) { throw "Publisher response for '$($form.Name)' is not a ZIP archive." }
    } finally { $stream.Dispose() }
    Move-Item -LiteralPath $temporary -Destination $target -ErrorAction Stop
    $observation = Get-JoeWareZipObservation -Path $target -ProductName $form.Name -Version $form.Version -VersionLabel $form.VersionLabel -PageUri $form.PageUri -VersionList $versionList
    $observation | Add-Member -NotePropertyName ResponseUri -NotePropertyValue $finalUri
    $observations += $observation
    if ($observation.PageVersionDiscrepancy -or $observation.ArchiveVersionDifference.Count) {
      Write-Warning "JoeWare version difference/candidate for $($form.Name) was recorded in the download manifest. Review docs/joeware-version-discrepancies.md and the archive contents before catalog admission."
    }
    [pscustomobject]$observation
  } finally {
    if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary -Force }
  }
}

if ($observations.Count) {
  $manifest = [ordered]@{
    SchemaVersion = 1
    RecordedAtUtc = [DateTime]::UtcNow.ToString('o')
    InventoryUri = [string]$inventory.Index.Uri
    VersionListUri = $versionList.Uri
    VersionListSha256 = $versionList.Sha256
    Scope = 'Selected members from the reviewed 41-product inventory.'
    PayloadsExecuted = $false
    PackagesInstalled = $false
    Products = @($observations)
  }
  $manifestPath = Join-Path $destination 'joeware-download-observations.json'
  $json = ConvertTo-Json -InputObject ([pscustomobject]$manifest) -Depth 8
  [IO.File]::WriteAllText($manifestPath, $json, [Text.UTF8Encoding]::new($false))
  Write-Output ([pscustomobject]@{ ManifestPath = $manifestPath; ProductCount = $observations.Count; PayloadsExecuted = $false })
}
