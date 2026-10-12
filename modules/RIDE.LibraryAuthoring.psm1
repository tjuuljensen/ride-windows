<#
.SYNOPSIS
  Generate a validated custom-library project from author-supplied data.
.DESCRIPTION
  Creates new projects or appends operations to a generated library. Stages and
  validates metadata before publication; append retains original metadata for
  recovery, checks versions/conflicts and rolls back failed writes.
  Does not download payloads, import the engine or invoke Windows handlers.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Owner: RIDE-Windows maintainers. Version: 0.5.0.
  Changelog: 0.5.0: Save incomplete package definitions as drafts and derive exact detection patterns from confirmed names.
    0.4.0: Author coordinated registry values and map HKCR to explicit scope roots.
    0.3.0: Add operations to existing libraries with versioned metadata recovery.
    0.2.0: Accept ZIP packaging and distinct installer-member digest fields.
    0.1.0: Add declarative project generation for the guided helper.
#>


Import-Module (Join-Path $PSScriptRoot 'RIDE.Libraries.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.LibrarySchema.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogValidation.psm1') -ErrorAction Stop
$ErrorActionPreference = 'Stop'

function ConvertTo-RideLibraryLiteral {
  param($Value, [int] $Indent = 0)
  if ($Indent -gt 20) { throw 'Authoring data exceeds the nesting limit.' }
  $padding = ' ' * $Indent
  if ($null -eq $Value) { return '$null' }
  if ($Value -is [bool]) { return ('$' + $Value.ToString().ToLowerInvariant()) }
  if ($Value -is [string]) { return ("'" + $Value.Replace("'", "''") + "'") }
  if ($Value -is [int]) { return $Value.ToString([Globalization.CultureInfo]::InvariantCulture) }
  if ($Value -is [long]) { return ($Value.ToString([Globalization.CultureInfo]::InvariantCulture) + 'L') }
  if ($Value -is [Collections.IDictionary]) {
    $lines = @('@{')
    foreach ($key in $Value.Keys | Sort-Object) {
      $lines += ($padding + '  ' + (ConvertTo-RideLibraryLiteral ([string]$key)) + ' = ' + (ConvertTo-RideLibraryLiteral $Value[$key] ($Indent + 2)))
    }
    return (($lines + ($padding + '}')) -join "`n")
  }
  if ($Value -is [array]) {
    $lines = @('@(')
    foreach ($item in $Value) { $lines += ($padding + '  ' + (ConvertTo-RideLibraryLiteral $item ($Indent + 2))) }
    return (($lines + ($padding + ')')) -join "`n")
  }
  throw "Unsupported authoring data type: $($Value.GetType().FullName)"
}

function Save-RideLibraryAuthoringDraft {
  <#
  .SYNOPSIS
    Save incomplete guided authoring answers for later package detection review.
  .DESCRIPTION
    Writes only a declarative definition, never a loadable library. Refuses to
    overwrite an existing draft and honors WhatIf. No Windows state is queried.
  .PARAMETER Path
    New .psd1 draft file path.
  .PARAMETER Definition
    Guided authoring hashtable to resume later.
  .EXAMPLE
    Save-RideLibraryAuthoringDraft -Path .\my-library.draft.psd1 -Definition $answers
  .INPUTS
    None.
  .OUTPUTS
    System.String. Absolute draft path when written.
  .NOTES
    Windows PowerShell 5.1 and PowerShell 7 on Windows. Version 0.5.0.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][hashtable] $Definition)
  $fullPath = [IO.Path]::GetFullPath($Path)
  if ([IO.Path]::GetExtension($fullPath) -ne '.psd1') { throw 'Authoring draft path must end in .psd1.' }
  $parent = Get-Item -LiteralPath (Split-Path -Parent $fullPath) -ErrorAction Stop
  if (-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Draft parent must be a regular directory.' }
  if (Test-Path -LiteralPath $fullPath) { throw "Draft already exists: $fullPath" }
  if (-not $PSCmdlet.ShouldProcess($fullPath, 'Save incomplete custom-library authoring draft')) { return }
  $contents = "# Incomplete RIDE library definition. Resume with New-RideLibrary.ps1 -Definition and -ResumeDraft.`n" + (ConvertTo-RideLibraryLiteral $Definition) + "`n"
  $bytes = [Text.UTF8Encoding]::new($false).GetBytes($contents)
  $stream = [IO.File]::Open($fullPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
  $fullPath
}

function ConvertTo-RideLibraryProjectData {
  param([hashtable] $Definition, [string] $Root)
  $options = Get-RideLibraryAuthoringOptions -Root $Root
  foreach ($field in $Definition.Keys) {
    if ($field -notin @('Id', 'Version', 'Operations')) { throw "Unknown library authoring field: $field" }
  }
  if ($Definition.Id -isnot [string] -or $Definition.Id -cnotmatch '^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$' -or
      $Definition.Version -isnot [string] -or $Definition.Version -notmatch '^\d+\.\d+\.\d+$' -or
      $Definition.Operations -isnot [array] -or -not $Definition.Operations.Count -or $Definition.Operations.Count -gt 128) { throw 'Provide a lowercase library Id, three-part Version and 1-128 Operations.' }
  $operations = @(); $selections = @()
  foreach ($inputOperation in $Definition.Operations) {
    if ($inputOperation -isnot [hashtable]) { throw 'Every authoring operation must be a hashtable.' }
    if ($inputOperation.Kind -notin $options.Kinds) { throw ('Choose a supported operation kind: ' + ($options.Kinds -join ', ')) }
    $common = @('Id', 'Name', 'Kind', 'Description', 'Category', 'Scope', 'SupportedTargets', 'TargetDefaults', 'RecoveryUri')
    $specific = if ($inputOperation.Kind -eq 'Package') {
      @('PackageId', 'InstallerType', 'Architecture', 'DownloadProvider', 'DownloadUri', 'PackageVersion', 'AssetName', 'ExpectedSha256',
        'AssetPattern', 'DisplayNamePattern', 'DetectionDisplayName', 'InstallerArguments', 'UninstallerArguments', 'SuccessExitCodes', 'ProductUri', 'License', 'LicenseUri', 'TermsUri', 'TagPrefix', 'PublisherChecksumSource', 'ArchiveType', 'InstallerEntry', 'ExpectedInstallerSha256')
    } elseif ($inputOperation.Kind -eq 'RegistryValueSet') { @('RegistryValues', 'States', 'BaselineState', 'DocumentationUri') }
    else { @('RegistryPath', 'ValueName', 'ValueType', 'States', 'BaselineState', 'DocumentationUri') }
    foreach ($field in $inputOperation.Keys) {
      if ($field -notin ($common + $specific)) { throw "Unknown $($inputOperation.Kind) authoring field: $field" }
    }
    foreach ($field in @('Id', 'Name', 'Description', 'Scope', 'SupportedTargets')) {
      if (-not $inputOperation.ContainsKey($field) -or -not $inputOperation[$field]) { throw "Required authoring field: $field" }
    }
    if ($inputOperation.Id -isnot [string] -or $inputOperation.Id -cnotmatch '^[a-z][a-z0-9.-]*$') { throw 'Operation Id must be a lowercase local name, such as my-app.' }
    if ($inputOperation.Scope -notin $options.Scopes -or @($inputOperation.SupportedTargets | Where-Object { $_ -notin $options.SupportedTargets }).Count) { throw 'Choose a supported scope and catalog target name.' }
    $operation = $inputOperation.Clone()
    $operation.Id = $Definition.Id + '.' + $inputOperation.Id
    $operation.Handler = $operation.Kind
    $operation.RequiresAdmin = ($operation.Scope -eq 'Machine')
    $operation.SupportedTargets = @($operation.SupportedTargets | Sort-Object -Unique)
    if (-not $operation.Category) { $operation.Category = if ($operation.Kind -eq 'Package') { 'Software / Custom library' } else { 'Windows settings / Custom library' } }
    if ($operation.Kind -eq 'Package') {
      if ($operation.ContainsKey('DetectionDisplayName')) {
        if ($operation.ContainsKey('DisplayNamePattern')) { throw 'Use either DetectionDisplayName or DisplayNamePattern for package detection.' }
        if ($operation.DetectionDisplayName -isnot [string] -or [string]::IsNullOrWhiteSpace($operation.DetectionDisplayName)) { throw 'Confirm DetectionDisplayName before publishing the package library.' }
        $operation.DisplayNamePattern = '^' + [regex]::Escape($operation.DetectionDisplayName) + '$'
        $operation.Remove('DetectionDisplayName')
      }
      if ($operation.InstallerType -notin $options.InstallerTypes -or $operation.DownloadProvider -notin $options.DownloadProviders -or $operation.Architecture -notin $options.Architectures) { throw 'Choose a supported installer, download provider and architecture.' }
      $operation.Actions = @('Get', 'Test', 'Download', 'Install', 'Uninstall', 'Restore')
      $operation.Rollback = 'Compensating'
      if (-not $operation.PackageId) { $operation.PackageId = $operation.Id }
      if (-not $operation.TargetDefaults) {
        $operation.TargetDefaults = @{}
        foreach ($target in $operation.SupportedTargets) { $operation.TargetDefaults[$target] = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Author-declared absent default; verify the target image' } }
      }
      $selections += @{ Id = $operation.Id; State = 'Present' }
    } else {
      if ($operation.States -isnot [hashtable] -or -not $operation.TargetDefaults) { throw 'Registry entries need States and declared TargetDefaults.' }
      if ($operation.Kind -eq 'RegistryValue') {
        if ($operation.ValueType -notin $options.RegistryValueTypes) { throw 'Registry entries need a supported ValueType.' }
        $operation.RegistryPath = ConvertTo-RideLibraryRegistryPath -Path $operation.RegistryPath -Scope $operation.Scope
      } else {
        $operation.RegistryValues = @($operation.RegistryValues | ForEach-Object {
          if ($_ -isnot [hashtable]) { throw 'Registry components must be hashtables.' }
          $member = $_.Clone()
          $member.RegistryPath = ConvertTo-RideLibraryRegistryPath -Path $member.RegistryPath -Scope $operation.Scope
          $member
        })
      }
      $operation.Actions = @('Get', 'Test', 'Set', 'Restore')
      $operation.Rollback = 'Exact'
      if (-not $operation.BaselineState) { throw 'Declare a registry BaselineState from its States.' }
      $state = @($operation.States.Keys | Where-Object { $_ -ne $operation.BaselineState } | Sort-Object | Select-Object -First 1)
      if (-not $state.Count) { throw 'Declare a selectable registry state besides the baseline.' }
      $selections += @{ Id = $operation.Id; State = $state[0] }
    }
    $operations += $operation
  }
  $manifest = @{ SchemaVersion = 1; Id = $Definition.Id; Version = $Definition.Version; EngineApiVersion = 1; Catalog = 'catalog/operations.psd1'; Profiles = @('profiles/custom.psd1') }
  $catalog = @{ SchemaVersion = 1; Operations = $operations; Groups = @() }
  $profile = @{ SchemaVersion = 1; Name = $Definition.Id; Description = 'Author-selected custom entries; review and preview before applying.'; Operations = $selections }
  $files = @{
    'ride-library.psd1' = $manifest
    'catalog/operations.psd1' = $catalog
    'profiles/custom.psd1' = $profile
  }
  $files
}

function New-RideLibraryProject {
  <#
  .SYNOPSIS
    Create a new, validated custom library without changing Windows state.
  .DESCRIPTION
    Expands authoring data into a manifest, catalog and profile. Uses the shared
    API choices and normal resolver before publishing. An existing output path
    is always refused, and WhatIf writes no files. No package is installed.
  .PARAMETER Path
    New project directory. Its parent must already exist; paths are literal.
  .PARAMETER Definition
    Hashtable with Id, Version and Operations. Operations use documented
    authoring fields; lifecycle wiring is supplied by this generator.
  .PARAMETER Root
    RIDE checkout used to resolve built-in references and supported choices.
  .EXAMPLE
    New-RideLibraryProject -Path .\my-library -Definition $definition -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Path, Manifest, Profile and OperationIds.
  .NOTES
    Files are staged in a temporary sibling directory, removed on validation
    failure. Keep published original library versions for saved-run recovery.
    Version and compatibility follow the module overview.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string] $Path,
    [Parameter(Mandatory)][hashtable] $Definition,
    [string] $Root = (Split-Path -Parent $PSScriptRoot)
  )
  $files = ConvertTo-RideLibraryProjectData -Definition $Definition -Root $Root
  $operations = $files['catalog/operations.psd1'].Operations
  $contents = @{}
  foreach ($file in $files.Keys) { $contents[$file] = "# Generated by New-RideLibrary.ps1; owned by the library author.`n" + (ConvertTo-RideLibraryLiteral $files[$file]) + "`n" }
  $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
  if (Test-Path -LiteralPath $fullPath) { throw "Output already exists; choose a new directory: $fullPath" }
  $parent = Get-Item -LiteralPath (Split-Path -Parent $fullPath) -ErrorAction Stop
  if (-not $parent.PSIsContainer) { throw 'The output parent must be a directory.' }
  if (-not $PSCmdlet.ShouldProcess($fullPath, 'Create validated custom-library manifest, catalog and profile')) { return }
  $staging = Join-Path $parent.FullName ('.ride-library-' + [guid]::NewGuid().ToString('N'))
  try {
    $null = [IO.Directory]::CreateDirectory($staging)
    foreach ($file in $contents.Keys) {
      $destination = Join-Path $staging $file
      $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
      [IO.File]::WriteAllText($destination, $contents[$file], [Text.UTF8Encoding]::new($false))
    }
    $null = Get-RideCatalogContext -Root $Root -Library (Join-Path $staging 'ride-library.psd1')
    # Moving the directory publishes all validated files together, without replacement.
    [IO.Directory]::Move($staging, $fullPath)
    [pscustomobject]@{ Path = $fullPath; Manifest = Join-Path $fullPath 'ride-library.psd1'; Profile = Join-Path $fullPath 'profiles/custom.psd1'; OperationIds = @($operations.Id) }
  }
  finally {
    if (Test-Path -LiteralPath $staging) {
      $resolved = (Get-Item -LiteralPath $staging).FullName
      if ($resolved -ne [IO.Path]::GetFullPath($staging) -or (Split-Path -Parent $resolved) -ne $parent.FullName -or (Split-Path -Leaf $resolved) -notmatch '^\.ride-library-[a-f0-9]{32}$') { throw 'Unexpected authoring cleanup path.' }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }
}

function Set-RideLibraryMetadataFile {
  param([string] $Source, [string] $Destination)
  [IO.File]::Replace($Source, $Destination, [NullString]::Value)
}

function Add-RideLibraryOperation {
  <#
  .SYNOPSIS
    Append declared operations to an existing generated custom library.
  .DESCRIPTION
    Preserves operation IDs, groups, existing profile selections and unrelated
    files. Requires the same namespace and a higher version. Validates staged
    metadata, retains original manifest/catalog/profiles in a sibling history
    directory, and restores original files on publication failure. A lock blocks
    library readers during publication. No engine, installer or Windows changes.
  .PARAMETER Path
    Existing generated library directory with ride-library.psd1, the standard
    catalog/operations.psd1 and a declared profiles/custom.psd1.
  .PARAMETER Definition
    Hashtable with the existing Id, a higher Version and new local Operations.
    Existing operations cannot be overwritten or renamed by this command.
  .PARAMETER Root
    RIDE checkout providing built-in references and API 1 validation.
  .EXAMPLE
    Add-RideLibraryOperation -Path .\my-library -Definition $newOperations -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Updated paths, added operation IDs and PreviousManifest.
  .NOTES
    WhatIf writes nothing. PreviousManifest resolves the exact prior catalog for
    saved-run recovery. History retains declared metadata, not unrelated assets.
    A crash or failed rollback may leave .ride-authoring.lock; recover the retained
    metadata before removing that marker. Version 0.4.0; Windows PowerShell 5.1/7.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string] $Path,
    [Parameter(Mandatory)][hashtable] $Definition,
    [string] $Root = (Split-Path -Parent $PSScriptRoot)
  )
  $directory = Get-Item -LiteralPath $Path -ErrorAction Stop
  if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Add requires a regular generated library directory.' }
  $fullPath = $directory.FullName
  $manifestPath = Join-Path $fullPath 'ride-library.psd1'
  $context = Get-RideCatalogContext -Root $Root -Library $manifestPath
  $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
  if ($manifest.Catalog -ne 'catalog/operations.psd1' -or 'profiles/custom.psd1' -notin $manifest.Profiles) { throw 'Add supports generated libraries with catalog/operations.psd1 and declared profiles/custom.psd1.' }
  $newFiles = ConvertTo-RideLibraryProjectData -Definition $Definition -Root $Root
  if ($Definition.Id -cne $manifest.Id) { throw 'Add must use the existing library namespace.' }
  if ([version]$Definition.Version -le [version]$manifest.Version) { throw 'Add requires a higher library version; retain original versions for recovery.' }
  $relativeFiles = @('ride-library.psd1', $manifest.Catalog) + @($manifest.Profiles)
  $originals = @{}; $hashes = @{}
  foreach ($relative in $relativeFiles) {
    $source = [IO.Path]::GetFullPath((Join-Path $fullPath $relative))
    if (-not $source.StartsWith($fullPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Metadata path escapes the library directory.' }
    $item = Get-Item -LiteralPath $source -ErrorAction Stop
    while ($item.FullName -ne $fullPath) {
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Add cannot replace linked metadata files or directories.' }
      $item = Get-Item -LiteralPath (Split-Path -Parent $item.FullName)
    }
    $originals[$relative] = [IO.File]::ReadAllBytes($source)
    $hashes[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
  }
  $oldCatalog = Import-RideCatalogData -Path (Join-Path $fullPath $manifest.Catalog)
  if ($hashes[$manifest.Catalog] -ne $context.Libraries[0].CatalogSha256 -or $manifest.Version -ne $context.Libraries[0].Version) { throw 'Library changed while reading; retry Add.' }
  $addedOperations = $newFiles['catalog/operations.psd1'].Operations
  $oldCatalog.Operations = @($oldCatalog.Operations) + @($addedOperations)
  $profile = Import-PowerShellDataFile -LiteralPath (Join-Path $fullPath 'profiles/custom.psd1')
  $profile.Operations = @($profile.Operations) + @($newFiles['profiles/custom.psd1'].Operations)
  $manifest.Version = $Definition.Version
  $combined = Get-RideCatalogContext -Root $Root
  $combined.Catalog.Operations = @($combined.Catalog.Operations) + @($oldCatalog.Operations)
  $combined.Catalog.Groups = @($combined.Catalog.Groups) + @($oldCatalog.Groups)
  $errors = @(Get-RideCatalogValidationErrors -Catalog $combined.Catalog -CustomOperationIds @($oldCatalog.Operations.Id))
  $packageIds = @{}; $duplicates = @()
  foreach ($package in ($combined.Catalog.Operations | Where-Object Kind -eq Package)) {
    if ($packageIds.ContainsKey($package.PackageId)) { $duplicates += $package.PackageId }
    $packageIds[$package.PackageId] = $true
  }
  if ($errors.Count -or $duplicates.Count) { throw ("Add validation failed: " + ($errors -join '; ') + $(if ($duplicates.Count) { ' Duplicate package ownership.' })) }
  $updates = @{ 'ride-library.psd1' = $manifest; 'catalog/operations.psd1' = $oldCatalog; 'profiles/custom.psd1' = $profile }
  if (-not $PSCmdlet.ShouldProcess($fullPath, "Add $($addedOperations.Count) operation(s), version $($Definition.Version), retaining previous metadata")) { return }
  $staging = Join-Path $directory.Parent.FullName ('.ride-library-add-' + [guid]::NewGuid().ToString('N'))
  $history = Join-Path ($fullPath + '.history') ($context.Libraries[0].Version + '-' + [guid]::NewGuid().ToString('N'))
  if (Test-Path -LiteralPath ($fullPath + '.history')) {
    $historyRoot = Get-Item -LiteralPath ($fullPath + '.history')
    if (-not $historyRoot.PSIsContainer -or ($historyRoot.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Library history must be a regular directory.' }
  }
  $lockPath = Join-Path $fullPath '.ride-authoring.lock'
  $lock = $null; $safeToUnlock = $true; $replaced = @()
  try {
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    foreach ($relative in $relativeFiles) {
      if ((Get-FileHash -LiteralPath (Join-Path $fullPath $relative)).Hash -ne $hashes[$relative]) { throw 'Library changed before publication; retry Add.' }
      $destination = Join-Path $staging $relative
      $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
      [IO.File]::WriteAllBytes($destination, $originals[$relative])
    }
    foreach ($relative in $updates.Keys) {
      $text = "# Generated by New-RideLibrary.ps1; owned by the library author.`n" + (ConvertTo-RideLibraryLiteral $updates[$relative]) + "`n"
      [IO.File]::WriteAllText((Join-Path $staging $relative), $text, [Text.UTF8Encoding]::new($false))
    }
    $null = Get-RideCatalogContext -Root $Root -Library (Join-Path $staging 'ride-library.psd1')
    foreach ($relative in $relativeFiles) {
      $destination = Join-Path $history $relative
      $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
      [IO.File]::WriteAllBytes($destination, $originals[$relative])
    }
    $lockBytes = [Text.Encoding]::UTF8.GetBytes("PreviousManifest: " + (Join-Path $history 'ride-library.psd1'))
    $lock.Write($lockBytes, 0, $lockBytes.Length); $lock.Flush()
    try {
      foreach ($relative in @('catalog/operations.psd1', 'profiles/custom.psd1', 'ride-library.psd1')) {
        $replaced += $relative
        Set-RideLibraryMetadataFile -Source (Join-Path $staging $relative) -Destination (Join-Path $fullPath $relative)
      }
    } catch {
      $publicationError = $_
      foreach ($relative in $replaced) {
        try {
          $rollback = Join-Path $staging ('rollback-' + [guid]::NewGuid().ToString('N') + '.psd1')
          [IO.File]::WriteAllBytes($rollback, $originals[$relative])
          Set-RideLibraryMetadataFile -Source $rollback -Destination (Join-Path $fullPath $relative)
        } catch { $safeToUnlock = $false; Write-Warning ("Could not restore '$relative'; recover using '$history' before removing '$lockPath'.") }
      }
      throw "Library publication failed: $($publicationError.Exception.Message). Previous metadata retained at '$history'."
    }
    [pscustomobject]@{ Path = $fullPath; Manifest = $manifestPath; Profile = Join-Path $fullPath 'profiles/custom.psd1'; OperationIds = @($addedOperations.Id); Version = $Definition.Version; PreviousManifest = Join-Path $history 'ride-library.psd1' }
  } finally {
    if ($lock) { $lock.Dispose(); if ($safeToUnlock) { Remove-Item -LiteralPath $lockPath -Force } }
    if ([IO.Directory]::Exists($staging)) {
      $resolved = (Get-Item -LiteralPath $staging).FullName
      if ($resolved -ne [IO.Path]::GetFullPath($staging) -or (Split-Path -Parent $resolved) -ne $directory.Parent.FullName -or (Split-Path -Leaf $resolved) -notmatch '^\.ride-library-add-[a-f0-9]{32}$') { throw 'Unexpected append staging cleanup path.' }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }
}

Export-ModuleMember -Function New-RideLibraryProject, Add-RideLibraryOperation, Save-RideLibraryAuthoringDraft
