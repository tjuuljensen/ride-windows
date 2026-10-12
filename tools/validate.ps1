<#
.SYNOPSIS
  Validate RIDE catalog, profiles, PowerShell syntax, and generated documentation.

.DESCRIPTION
  Checks the resolved built-in/selected library catalog schema, operation lifecycle, references, artifact observations, profile
  selections, and script parsing. Invokes the catalog generator in Check mode. Throws aggregated
  validation failures; does not invoke handlers or installers.

.PARAMETER Root
  Repository root; defaults to the parent of the tools directory.

.PARAMETER Library
  Explicit local library manifest paths to validate with the built-in catalog and profiles.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\tools\validate.ps1

.EXAMPLE
  .\tools\validate.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Progress and diagnostic messages.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Windows-native PowerShell; a complete repository checkout with generated operation
  documentation.
  File/environment inputs: Catalog, artifact observation JSON, profile data files, and repository
  PowerShell sources.
  Recovery: Read-only checks; fix authoritative inputs before regenerating documentation.
  Author: RIDE-Windows maintainers.
  Version: 0.10.0
  Changelog:
    0.10.0: Exclude private local configuration and diagnostic scripts from source validation.
  - 0.9.0: Preserve required built-in references while allowing optional custom links.
  - 0.8.0: Share catalog validation and include explicitly selected metadata libraries.
  - 0.7.0: Validate focused managed-setting identities, states, scope and references.
  - 0.6.0: Validate coordinated registry states, boot recovery and power timeout indexes.
  - 0.5.0: Validate publisher license references and keep local reviews out of the catalog.
  - 0.4.0: Validate nullable registry default existence for image-dependent values.
  - 0.3.0: Validate the desktop Shell folder metadata and profile states.
  - 0.2.0: Validate larger catalogs, MSI lifecycle metadata and prerequisites.
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

#>


[CmdletBinding()]
param([string] $Root = '',
  [string[]] $Library = @(),
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.10.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$errors = New-Object System.Collections.Generic.List[string]

function Add-Error([string] $Message) { $errors.Add($Message) }

$catalogPath = Join-Path $Root 'catalog/operations.psd1'
$profilePaths = @(Get-ChildItem -LiteralPath (Join-Path $Root 'profiles') -Filter '*.psd1' -File)
Import-Module (Join-Path $Root 'modules/RIDE.CatalogData.psm1') -Force
$catalog = Import-RideCatalogData -Path $catalogPath
if ($Library.Count) {
  Import-Module (Join-Path $Root 'modules/RIDE.Libraries.psm1') -ErrorAction Stop
  $context = Get-RideCatalogContext -Root $Root -Library $Library
  $catalog = $context.Catalog
  $profilePaths = $context.ProfileFiles
}
if ($catalog.SchemaVersion -ne 1) { Add-Error 'Catalog must declare SchemaVersion 1.' }

$artifactObservationPath = Join-Path $Root 'catalog/artifact-observations.json'
try {
  $artifactLibrary = Get-Content -LiteralPath $artifactObservationPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
  if ($artifactLibrary.SchemaVersion -ne 1 -or 'Observations' -notin $artifactLibrary.PSObject.Properties.Name) { Add-Error 'Artifact observation library must declare SchemaVersion 1 and an Observations array.' }
  foreach ($observation in @($artifactLibrary.Observations)) {
    foreach ($field in @('Version', 'FileName', 'OriginUri', 'SourceUri', 'ObservedAtUtc', 'Route', 'Sha256')) {
      if (-not $observation.$field) { Add-Error "Artifact observation is missing '$field'." }
    }
    if (-not $observation.PackageId -and -not $observation.ArtifactId) { Add-Error 'Artifact observation must identify a package or artifact.' }
    if ($observation.Sha256 -notmatch '^[0-9a-f]{64}$') { Add-Error "Artifact observation has an invalid SHA-256 for '$($observation.PackageId)' $($observation.Version)." }
    foreach ($uriField in @('SourceUri', 'OriginUri')) {
      if (-not [Uri]::IsWellFormedUriString([string]$observation.$uriField, [UriKind]::Absolute) -or ([Uri]$observation.$uriField).Scheme -ne 'https') { Add-Error "Artifact observation '$uriField' must be an absolute HTTPS URI for '$($observation.PackageId)' $($observation.Version)." }
    }
  }
}
catch { Add-Error "Artifact observation library is invalid: $($_.Exception.Message)" }

Import-Module (Join-Path $Root 'modules/RIDE.CatalogValidation.psm1') -ErrorAction Stop
foreach ($diagnostic in @(Get-RideCatalogValidationErrors -Catalog $catalog -ProfilePaths $profilePaths -CustomOperationIds @($catalog.Operations | Where-Object Library | ForEach-Object Id))) { Add-Error $diagnostic }

$powershellFiles = Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object {
  $_.Extension -in @('.ps1', '.psm1') -and $_.FullName -notmatch '[\\/](\.git|\.vs|\.local)[\\/]'
}
foreach ($file in $powershellFiles) {
  $tokens = $null
  $parseErrors = $null
  [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
  foreach ($parseError in $parseErrors) {
    Add-Error ("{0}:{1}: {2}" -f $file.FullName.Substring($Root.Length + 1), $parseError.Extent.StartLineNumber, $parseError.Message)
  }
}

try {
  & (Join-Path $PSScriptRoot 'Export-RideCatalog.ps1') -Root $Root -Check
}
catch { Add-Error $_.Exception.Message }

if ($errors.Count -gt 0) { throw ("Validation failed with {0} error(s):`n{1}" -f $errors.Count, ($errors -join "`n")) }
Write-Output ("Validation passed. Checked {0} operation(s), {1} group(s), {2} profile(s), and {3} PowerShell file(s)." -f $catalog.Operations.Count, $catalog.Groups.Count, $profilePaths.Count, $powershellFiles.Count)
