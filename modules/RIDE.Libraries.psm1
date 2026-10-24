<#
.SYNOPSIS
  Resolve explicitly selected local RIDE libraries as declarative metadata.
.DESCRIPTION
  Merges catalogs, validates references and exposes declared profile files.
  Loads no operational modules, runs no handlers and makes no network requests.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: RIDE.CatalogData.psm1 and RIDE.CatalogValidation.psm1.
  Owner: RIDE-Windows maintainers. Version: 0.4.0. Library API: 1.
  Changelog: 0.4.0: Accept custom coordinated registry values and unnamed defaults.
    0.3.0: Reject libraries being updated or changed during metadata reads.
    0.2.0: Share authoring choices and allow optional custom reference links.
  Changelog: 0.1.0: Add local manifest loading, shared metadata and recovery identity.
#>


Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.LibrarySchema.psm1') -ErrorAction Stop
$ErrorActionPreference = 'Stop'

function Test-RideLibraryRegistryValue {
  param([string] $Type, $Value)
  if ($null -eq $Value) { return $true }
  switch ($Type) {
    { $_ -in @('String', 'ExpandString') } { return ($Value -is [string]) }
    DWord { return ($Value -is [int]) }
    QWord { return ($Value -is [int] -or $Value -is [long]) }
    Binary { return ($Value -is [array] -and @($Value | Where-Object { $_ -isnot [int] -or $_ -lt 0 -or $_ -gt 255 }).Count -eq 0) }
    default { return $false }
  }
}

function Read-RideLibraryData {
  param([string] $Path)
  $file = Get-Item -LiteralPath $Path -ErrorAction Stop
  if ($file.PSIsContainer -or $file.Extension -ne '.psd1' -or $file.Length -gt 256KB) { throw "Expected a bounded .psd1 data file: $Path" }
  $tokens = $null; $errors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
  if ($errors.Count -or $ast.BeginBlock -or $ast.ProcessBlock -or $ast.ParamBlock -or $ast.EndBlock.Statements.Count -ne 1) { throw "Invalid declarative library data: $Path" }
  $statement = $ast.EndBlock.Statements[0]
  if ($statement -isnot [Management.Automation.Language.PipelineAst] -or $statement.PipelineElements.Count -ne 1 -or
      $statement.PipelineElements[0].Expression -isnot [Management.Automation.Language.HashtableAst]) { throw "Library data must contain only a hashtable: $Path" }
  $statement.PipelineElements[0].Expression.SafeGetValue()
}

function Get-RideLibraryFile {
  param([string] $Root, [string] $RelativePath)
  if ([string]::IsNullOrWhiteSpace($RelativePath) -or [IO.Path]::IsPathRooted($RelativePath) -or
      $RelativePath -match '(^|[\\/])\.\.([\\/]|$)|[:*?]' -or $RelativePath -match '[\r\n]') { throw "Library paths must be relative files inside the library: $RelativePath" }
  $path = [IO.Path]::GetFullPath((Join-Path $Root $RelativePath))
  if (-not $path.StartsWith($Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Library path escapes its root.' }
  $file = Get-Item -LiteralPath $path -ErrorAction Stop
  if ($file.PSIsContainer -or $file.Extension -ne '.psd1') { throw "Expected a library .psd1 file: $path" }
  $file
}

function Get-RideCatalogContext {
  <#
  .SYNOPSIS
    Resolve the built-in catalog and explicitly selected local libraries.
  .PARAMETER Root
    RIDE checkout root, containing catalog/operations.psd1 and profiles.
  .PARAMETER Library
    Literal local manifest paths. At most 32 manifests; references resolve across all selections.
  .EXAMPLE
    Get-RideCatalogContext -Root . -Library .\examples\contoso\ride-library.psd1
  .INPUTS
    None.
  .OUTPUTS
    System.Collections.Hashtable. Catalog, ProfileFiles and Libraries.
  .NOTES
    Library API 1 supports RegistryValue, RegistryValueSet and Package metadata
    using built-in handlers. Registry paths must use explicit scope roots.
    Resolves data only. No module discovery, installation or custom code execution.
  #>
  [CmdletBinding()]
  param([string] $Root = (Split-Path -Parent $PSScriptRoot), [string[]] $Library = @())
  $rootPath = (Get-Item -LiteralPath $Root -ErrorAction Stop).FullName
  $catalog = Import-RideCatalogData -Path (Join-Path $rootPath 'catalog/operations.psd1')
  $profileFiles = @(Get-ChildItem -LiteralPath (Join-Path $rootPath 'profiles') -Filter '*.psd1' -File -ErrorAction SilentlyContinue)
  $libraries = @()
  if ($Library.Count -gt 32) { throw 'Select at most 32 libraries.' }
  if (-not $Library.Count) { return @{ Catalog = $catalog; ProfileFiles = $profileFiles; Libraries = @() } }
  $options = Get-RideLibraryAuthoringOptions -Root $rootPath
  Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogValidation.psm1') -ErrorAction Stop
  $libraryIds = @{}; $manifestPaths = @{}; $externalProfiles = @(); $externalGroups = @()
  foreach ($manifestPath in $Library) {
    $file = Get-Item -LiteralPath $manifestPath -ErrorAction Stop
    $authoringLock = Join-Path $file.DirectoryName '.ride-authoring.lock'
    if (Test-Path -LiteralPath $authoringLock) { throw "Library authoring is in progress or needs recovery: '$authoringLock'. Retry after publication, or recover retained metadata before removing a stale lock." }
    $manifestHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    if ($manifestPaths.ContainsKey($file.FullName)) { throw "Duplicate library selection: $manifestPath" }
    $manifestPaths[$file.FullName] = $true
    $manifest = Read-RideLibraryData -Path $file.FullName
    foreach ($key in $manifest.Keys) {
      if ($key -notin @('SchemaVersion', 'Id', 'Version', 'EngineApiVersion', 'Catalog', 'Profiles')) { throw "Unsupported library manifest field '$key'. Custom handlers are not supported by library API 1." }
    }
    foreach ($key in @('SchemaVersion', 'Id', 'Version', 'EngineApiVersion', 'Catalog', 'Profiles')) {
      if (-not $manifest.ContainsKey($key)) { throw "Library manifest is missing '$key': $manifestPath" }
    }
    if ($manifest.SchemaVersion -isnot [int] -or $manifest.SchemaVersion -ne 1 -or
        $manifest.EngineApiVersion -isnot [int] -or $manifest.EngineApiVersion -ne 1) { throw 'Unsupported library schema or engine API version; this engine supports library API 1.' }
    if ($manifest.Id -isnot [string] -or $manifest.Id -cnotmatch '^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$' -or
        $manifest.Version -isnot [string] -or $manifest.Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Library ID and three-part version are required.' }
    if ($libraryIds.ContainsKey($manifest.Id)) { throw "Duplicate library ID: $($manifest.Id)" }
    $libraryIds[$manifest.Id] = $true
    if ($manifest.Catalog -isnot [string] -or $manifest.Profiles -isnot [array] -or $manifest.Profiles.Count -gt 128) { throw 'Catalog must be a relative path; Profiles must be an array of at most 128 paths.' }
    $catalogFile = Get-RideLibraryFile -Root $file.DirectoryName -RelativePath $manifest.Catalog
    $catalogHash = (Get-FileHash -LiteralPath $catalogFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $additional = Import-RideCatalogData -Path $catalogFile.FullName
    $identity = @{
      Id = $manifest.Id; Version = $manifest.Version; EngineApiVersion = 1
      CatalogSha256 = $catalogHash
      SnapshotSchemaVersion = 1
    }
    foreach ($entry in @($additional.Operations) + @($additional.Groups)) {
      if ($entry.Id -isnot [string] -or -not $entry.Id.StartsWith($manifest.Id + '.', [StringComparison]::Ordinal) -or
          $entry.Id -cnotmatch '^[a-z][a-z0-9.-]+$') { throw "External IDs must use the library prefix '$($manifest.Id).': $($entry.Id)" }
      if ($entry.ContainsKey('Library')) { throw "Library ownership is assigned by the resolver: $($entry.Id)" }
    }
    foreach ($operation in $additional.Operations) {
      if ($operation.Kind -notin $options.Kinds -or $operation.Handler -ne $operation.Kind) { throw "Library API 1 supports only RegistryValue, RegistryValueSet and Package built-in handlers: $($operation.Id)" }
      if ($operation.RequiresAdmin -isnot [bool] -or $operation.RequiresAdmin -ne ($operation.Scope -eq 'Machine')) { throw "Invalid library scope/elevation metadata: $($operation.Id)" }
      if ($operation.Kind -eq 'Package' -and ($operation.PackageId -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]*$' -or
          'Download' -notin $operation.Actions -or $operation.InstallerType -notin $options.InstallerTypes -or
          $operation.DownloadProvider -notin $options.DownloadProviders)) { throw "External packages require a safe PackageId, supported source, Download action and EXE/MSI installer: $($operation.Id)" }
      if ($operation.Kind -eq 'RegistryValue' -and ($operation.States -isnot [hashtable] -or
          $operation.RegistryPath -notmatch $(if ($operation.Scope -eq 'User') { '^HKCU:\\' } else { '^HKLM:\\' }) -or
          $operation.ValueType -notin $options.RegistryValueTypes -or $operation.ValueName -isnot [string] -or
          @('Get', 'Test', 'Set', 'Restore' | Where-Object { $_ -notin $operation.Actions }).Count)) { throw "Invalid external registry lifecycle: $($operation.Id)" }
      if ($operation.Kind -eq 'RegistryValue') {
        foreach ($state in $operation.States.Keys) {
          if ($state -isnot [string] -or [string]::IsNullOrWhiteSpace($state) -or -not (Test-RideLibraryRegistryValue -Type $operation.ValueType -Value $operation.States[$state])) { throw "Invalid registry state value '$state': $($operation.Id)" }
        }
      }
      if ($operation.Kind -eq 'RegistryValueSet') {
        if ($operation.States -isnot [hashtable] -or $operation.RegistryValues -isnot [array] -or
            $operation.RegistryValues.Count -lt 2 -or $operation.RegistryValues.Count -gt 20) { throw "External registry value sets require States and 2-20 components: $($operation.Id)" }
        foreach ($member in $operation.RegistryValues) {
          if ($member -isnot [hashtable] -or $member.ValueName -isnot [string] -or
              $member.RegistryPath -notmatch $(if ($operation.Scope -eq 'User') { '^HKCU:\\' } else { '^HKLM:\\' }) -or
              $member.ValueType -notin $options.RegistryValueSetTypes) { throw "Invalid external registry component or scope: $($operation.Id)" }
        }
      }
      $operation.Library = $identity.Clone()
      $operation.Library.Handler = $operation.Handler
    }
    $catalog.Operations = @($catalog.Operations) + @($additional.Operations)
    $catalog.Groups = @($catalog.Groups) + @($additional.Groups)
    $externalGroups += @($additional.Groups)
    foreach ($group in $additional.Groups) {
      foreach ($field in @('Name', 'Category', 'Description', 'Members', 'Actions', 'Rollback')) {
        if (-not $group.ContainsKey($field)) { throw "External group is missing '$field': $($group.Id)" }
      }
      $group.Library = $identity.Clone()
    }
    if ($catalog.Operations.Count + $catalog.Groups.Count -gt 2000) { throw 'Resolved catalog exceeds the 2000 entry limit.' }
    $declaredProfiles = @{}
    foreach ($relativeProfile in $manifest.Profiles) {
      if ($relativeProfile -isnot [string]) { throw 'Profile paths must be strings.' }
      $profile = Get-RideLibraryFile -Root $file.DirectoryName -RelativePath $relativeProfile
      if ($declaredProfiles.ContainsKey($profile.FullName)) { throw "Duplicate library profile: $relativeProfile" }
      $declaredProfiles[$profile.FullName] = $true
      $null = Read-RideLibraryData -Path $profile.FullName
      $externalProfiles += $profile
    }
    if ((Test-Path -LiteralPath $authoringLock) -or (Get-FileHash -LiteralPath $file.FullName).Hash -ne $manifestHash -or
        (Get-FileHash -LiteralPath $catalogFile.FullName).Hash -ne $catalogHash) { throw 'Library metadata changed while being read; retry after authoring finishes.' }
    $libraries += [pscustomobject]@{ Id = $manifest.Id; Version = $manifest.Version; Path = $file.FullName; CatalogSha256 = $identity.CatalogSha256 }
  }
  $packageIds = @{}
  foreach ($package in $catalog.Operations | Where-Object Kind -eq 'Package') {
    if ($packageIds.ContainsKey($package.PackageId)) { throw "Duplicate package ownership for '$($package.PackageId)'; reference the existing operation ID instead." }
    $packageIds[$package.PackageId] = $true
  }
  $diagnostics = @(Get-RideCatalogValidationErrors -Catalog $catalog -ProfilePaths $externalProfiles -CustomOperationIds @($catalog.Operations | Where-Object Library | ForEach-Object Id))
  if ($diagnostics.Count) { throw ("Library catalog validation failed:`n" + ($diagnostics -join "`n")) }
  foreach ($group in $externalGroups) {
    foreach ($member in $group.Members) {
      if (($catalog.Operations | Where-Object Id -eq $member).Kind -ne 'Package') { throw "External groups must contain packages: $($group.Id)" }
    }
  }
  @{ Catalog = $catalog; ProfileFiles = @($profileFiles) + @($externalProfiles); Libraries = $libraries }
}

Export-ModuleMember -Function Get-RideCatalogContext
