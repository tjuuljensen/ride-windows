<#
.SYNOPSIS
  Read, update, export, or import local user/company package license reviews.
.DESCRIPTION
  Keeps versioned JSON reviews outside the shared catalog. Get joins public references
  with local records without creating files. Set and import preserve other reviews;
  import rejects conflicts unless Force is selected. Writes are locked and atomic.
  Does not download software, accept terms, invoke handlers, or approve redistribution.
.PARAMETER Command
  Get (default), Set, Export, or Import. Press Tab to complete declared commands.
.PARAMETER Id
  Catalog package or artifact ID. Required for Set; optional filter for Get.
  Tab completion reads only the bounded catalog reader.
.PARAMETER ReviewedVersion
  Exact upstream version or artifact commit revision covered by this review. Required for Set.
.PARAMETER ReviewOwner
  Individual or company responsible for the review. Required for Set.
.PARAMETER LicenseReviewStatus
  Unknown, NeedsReview, or Reviewed. Required for Set; Tab completes the declared values.
.PARAMETER DistributionNotes
  Local findings and intended use. Defaults to an empty string for Set.
.PARAMETER LicenseReviewedAt
  ISO 8601 timestamp with Z or an explicit UTC offset. Reviewed defaults to the current UTC time.
.PARAMETER StorePath
  Local JSON file. Defaults to LocalApplicationData/RIDE/license-reviews.json.
  Supply an access-controlled company file explicitly when appropriate.
.PARAMETER Path
  Export destination or import source JSON file. Required for Export and Import.
.PARAMETER Force
  Allow overwriting an export file or replacing conflicting imported reviews.
.PARAMETER Help
  Display native help before reading any data.
.PARAMETER Version
  Print the script version before reading any data.
.EXAMPLE
  .\tools\Manage-RideLicenseReviews.ps1 Get -Id package.7zip
.EXAMPLE
  .\tools\Manage-RideLicenseReviews.ps1 Set -Id package.7zip -ReviewedVersion 26.04 -ReviewOwner 'Example company' -LicenseReviewStatus Reviewed -DistributionNotes 'Internal workstation installation reviewed.' -WhatIf
.EXAMPLE
  .\tools\Manage-RideLicenseReviews.ps1 Export -Path C:\private\license-reviews.json
.EXAMPLE
  .\tools\Manage-RideLicenseReviews.ps1 Import -Path C:\private\license-reviews.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  System.Management.Automation.PSCustomObject. Joined review rows or write result paths/counts.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Catalog read access; local storage write access for mutations. No elevation required.
  File/environment inputs: catalog/operations.psd1 and the selected local JSON store.
  Recovery: Export before edits. Imports merge by ID, version, and owner; preserve source exports.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Separate local license reviews from shared publisher metadata.
.LINK
  ../docs/PACKAGE-LICENSING.md
#>


[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Position = 0)][ValidateSet('Get', 'Set', 'Export', 'Import')][string] $Command = 'Get',
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $scriptPath = (Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Source
      }
      $scriptPath = (Resolve-Path -LiteralPath $scriptPath).Path
      $root = Split-Path -Parent (Split-Path -Parent $scriptPath)
      Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      $catalog = Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')
      foreach ($candidate in @($catalog.Operations | Where-Object { $_.Kind -in @('Package', 'Artifact') } | ForEach-Object { $_.Id } | Sort-Object -Unique)) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) {
          [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate)
        }
      }
    }
    catch { } # Optional completion data must fail quietly.
  })][string] $Id,
  [string] $ReviewedVersion,
  [string] $ReviewOwner,
  [ValidateSet('Unknown', 'NeedsReview', 'Reviewed')][string] $LicenseReviewStatus,
  [string] $DistributionNotes = '',
  [string] $LicenseReviewedAt,
  [string] $StorePath = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RIDE/license-reviews.json'),
  [string] $Path,
  [switch] $Force,
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }
$ErrorActionPreference = 'Stop'

function Resolve-ReviewFilePath([string] $Value) {
  if ([string]::IsNullOrWhiteSpace($Value) -or [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Value)) { throw 'Review file paths must be literal paths without wildcards.' }
  $provider = $null
  $drive = $null
  $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Value, [ref]$provider, [ref]$drive)
  if ($provider.Name -ne 'FileSystem') { throw 'Review files require a FileSystem path.' }
  $resolved
}

function ConvertTo-ReviewTimestamp([string] $Value) {
  $parsed = [DateTimeOffset]::MinValue
  if ($Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$' -or
      -not [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) { throw 'LicenseReviewedAt requires an ISO 8601 timestamp with a UTC offset.' }
  $parsed.UtcDateTime.ToString('o')
}

function Get-ReviewKey($Record) {
  # JSON array encoding avoids collisions from delimiter characters in owner names.
  ConvertTo-Json -InputObject @($Record.Id.ToLowerInvariant(), $Record.ReviewedVersion.ToLowerInvariant(), $Record.ReviewOwner.ToLowerInvariant()) -Compress
}

function ConvertTo-ReviewDocument($Document) {
  if ($null -eq $Document -or $Document.SchemaVersion -ne 1 -or $Document.Reviews -isnot [array] -or
      @($Document.PSObject.Properties.Name | Where-Object { $_ -notin @('SchemaVersion', 'Reviews') }).Count -gt 0) { throw 'License review JSON requires SchemaVersion 1 and a Reviews array.' }
  if ($Document.Reviews.Count -gt 2000) { throw 'License review store exceeds 2000 records.' }
  $keys = @{}
  $records = foreach ($record in $Document.Reviews) {
    $fields = @('Id', 'ReviewedVersion', 'ReviewOwner', 'LicenseReviewStatus', 'DistributionNotes', 'LicenseReviewedAt')
    if (@($record.PSObject.Properties.Name).Count -ne $fields.Count -or @($fields | Where-Object { $_ -notin $record.PSObject.Properties.Name }).Count -gt 0) { throw 'License review record has missing or unexpected fields.' }
    foreach ($field in @('Id', 'ReviewedVersion', 'ReviewOwner', 'LicenseReviewStatus', 'DistributionNotes')) {
      if ($record.$field -isnot [string]) { throw "License review '$field' must be a string." }
    }
    if ($record.Id -notmatch '^(package|artifact)\.[a-z0-9][a-z0-9.-]*$' -or $record.ReviewedVersion -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}$' -or
        [string]::IsNullOrWhiteSpace($record.ReviewOwner) -or $record.ReviewOwner.Length -gt 256 -or $record.DistributionNotes.Length -gt 16384 -or
        $record.LicenseReviewStatus -cnotin @('Unknown', 'NeedsReview', 'Reviewed')) { throw 'Invalid license review identity, status, or text length.' }
    $timestamp = $null
    if ($null -ne $record.LicenseReviewedAt) {
      if ($record.LicenseReviewedAt -isnot [string]) { throw 'LicenseReviewedAt must be a timestamp string or null.' }
      $timestamp = ConvertTo-ReviewTimestamp $record.LicenseReviewedAt
    }
    if ($record.LicenseReviewStatus -eq 'Reviewed' -and -not $timestamp) { throw 'Reviewed records require LicenseReviewedAt.' }
    $normalized = [pscustomobject][ordered]@{
      Id = $record.Id.ToLowerInvariant()
      ReviewedVersion = $record.ReviewedVersion
      ReviewOwner = $record.ReviewOwner.Trim()
      LicenseReviewStatus = $record.LicenseReviewStatus
      DistributionNotes = $record.DistributionNotes
      LicenseReviewedAt = $timestamp
    }
    $key = Get-ReviewKey $normalized
    if ($keys.ContainsKey($key)) { throw 'Duplicate ID/version/owner in license review JSON.' }
    $keys[$key] = $true
    $normalized
  }
  [pscustomobject][ordered]@{ SchemaVersion = 1; Reviews = @($records | Sort-Object Id, ReviewedVersion, ReviewOwner) }
}

function Read-ReviewDocument([string] $FilePath) {
  if (-not (Test-Path -LiteralPath $FilePath)) { return [pscustomobject][ordered]@{ SchemaVersion = 1; Reviews = @() } }
  $file = Get-Item -LiteralPath $FilePath
  if ($file.PSIsContainer -or $file.Length -gt 4MB) { throw 'License review input must be a file no larger than 4 MiB.' }
  # PowerShell 7.5+ otherwise turns ISO strings into DateTime values; 5.1 keeps strings.
  $jsonOptions = @{}
  if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $jsonOptions.DateKind = 'String' }
  ConvertTo-ReviewDocument (Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8 | ConvertFrom-Json @jsonOptions)
}

function Write-ReviewDocument([string] $FilePath, $Document, [bool] $AllowOverwrite) {
  $json = $Document | ConvertTo-Json -Depth 6
  $json = $json.Replace("`r`n", "`n") + "`n"
  if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 4MB) { throw 'License review output exceeds 4 MiB.' }
  $temporaryPath = $FilePath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
  try {
    [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($false))
    if ([IO.File]::Exists($FilePath) -and $AllowOverwrite) { [IO.File]::Replace($temporaryPath, $FilePath, [NullString]::Value) }
    else { [IO.File]::Move($temporaryPath, $FilePath) }
  }
  finally { if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force } }
}

$StorePath = Resolve-ReviewFilePath $StorePath
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.CatalogData.psm1') -Force
$catalog = Import-RideCatalogData -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
$operations = @($catalog.Operations | Where-Object { $_.Kind -in @('Package', 'Artifact') })
if ($Id -and $Command -in @('Get', 'Set') -and $Id -notin @($operations.Id)) { throw "Unknown package or artifact ID: $Id" }
if ($Command -eq 'Get') {
  $document = Read-ReviewDocument $StorePath
  $allIds = @(@($operations.Id) + @($document.Reviews.Id) | Sort-Object -Unique)
  foreach ($entryId in $allIds) {
    if ($Id -and $entryId -ne $Id) { continue }
    $operation = $operations | Where-Object { $_.Id -eq $entryId } | Select-Object -First 1
    $reviews = @($document.Reviews | Where-Object { $_.Id -eq $entryId })
    if ($reviews.Count -eq 0) { $reviews = @($null) }
    foreach ($review in $reviews) {
      [pscustomobject][ordered]@{
        Id = $entryId; Name = $operation.Name; ProductUri = $operation.ProductUri
        License = $operation.License; LicenseUri = $operation.LicenseUri; TermsUri = $operation.TermsUri
        ReviewedVersion = $review.ReviewedVersion; ReviewOwner = $review.ReviewOwner
        LicenseReviewStatus = if ($review) { $review.LicenseReviewStatus } else { 'Unknown' }
        DistributionNotes = $review.DistributionNotes; LicenseReviewedAt = $review.LicenseReviewedAt
      }
    }
  }
  return
}

$incoming = $null
if ($Command -eq 'Set') {
  if (-not $Id -or -not $ReviewedVersion -or -not $ReviewOwner -or -not $LicenseReviewStatus) { throw 'Set requires Id, ReviewedVersion, ReviewOwner, and LicenseReviewStatus.' }
  $canonicalStatus = @('Unknown', 'NeedsReview', 'Reviewed') | Where-Object { $_ -eq $LicenseReviewStatus }
  $timestamp = if ($LicenseReviewedAt) { ConvertTo-ReviewTimestamp $LicenseReviewedAt } elseif ($canonicalStatus -eq 'Reviewed') { [DateTime]::UtcNow.ToString('o') } else { $null }
  $incoming = ConvertTo-ReviewDocument ([pscustomobject]@{ SchemaVersion = 1; Reviews = @([pscustomobject]@{
    Id = $Id; ReviewedVersion = $ReviewedVersion; ReviewOwner = $ReviewOwner
    LicenseReviewStatus = $canonicalStatus; DistributionNotes = $DistributionNotes; LicenseReviewedAt = $timestamp
  }) })
}
else {
  $Path = Resolve-ReviewFilePath $Path
  if ($Path -eq $StorePath) { throw 'Import/export Path must differ from StorePath.' }
  if ($Command -eq 'Import') {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Import file does not exist: $Path" }
    $incoming = Read-ReviewDocument $Path
  }
}

$targetPath = if ($Command -eq 'Export') { $Path } else { $StorePath }
if ($Command -eq 'Export' -and (Test-Path -LiteralPath $targetPath) -and -not $Force) { throw 'Export destination exists; select Force to overwrite it.' }
if (-not $PSCmdlet.ShouldProcess($targetPath, "$Command license review JSON")) { return }
$storeLock = $null
try {
  [IO.Directory]::CreateDirectory((Split-Path -Parent $targetPath)) | Out-Null
  $storeLock = [IO.File]::Open($targetPath + '.lock', [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  $document = Read-ReviewDocument $StorePath
  if ($Command -ne 'Export') {
    $merged = @{}
    foreach ($record in $document.Reviews) { $merged[(Get-ReviewKey $record)] = $record }
    foreach ($record in $incoming.Reviews) {
      $key = Get-ReviewKey $record
      if ($Command -eq 'Import' -and $merged.ContainsKey($key) -and -not $Force -and
          ($merged[$key] | ConvertTo-Json -Compress) -cne ($record | ConvertTo-Json -Compress)) { throw 'Conflicting imported review; select Force to replace it.' }
      $merged[$key] = $record
    }
    $document = ConvertTo-ReviewDocument ([pscustomobject]@{ SchemaVersion = 1; Reviews = @($merged.Values) })
  }
  Write-ReviewDocument $targetPath $document ($Command -ne 'Export' -or $Force.IsPresent)
  [pscustomobject]@{ Path = $targetPath; ReviewCount = $document.Reviews.Count }
}
finally { if ($storeLock) { $storeLock.Dispose() } }
