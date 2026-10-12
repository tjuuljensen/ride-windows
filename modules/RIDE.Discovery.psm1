<#
.SYNOPSIS
  Discover and search RIDE catalog metadata without loading system handlers.
.DESCRIPTION
  Uses the bounded data-only reader. Shares catalog rows and view selection with
  list; literal search examines only explicitly declared searchable fields.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: RIDE.CatalogData.psm1 and the declarative operation catalog.
  Owner: RIDE-Windows maintainers. Version: 0.4.0.
  Changelog: 0.4.0: Expose setting scope, behavior, GUI and requirement evidence gaps.
    0.3.0: Expose catalog package variants and defaults without loading handlers.
    0.2.0: Search resolved external catalog metadata without handlers.
    0.1.0: Add literal catalog search, match evidence and shared views.
#>

$script:ModuleVersion = '0.4.0'

Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.SettingPresentation.psm1') -ErrorAction Stop

# This map is the search contract, including the source of field completion.
$script:SearchFields = [ordered]@{
  Id = @('Id')
  Name = @('Name')
  Description = @('Description')
  Category = @('Category')
  RegistryPath = @('RegistryPath', 'RegistryPaths', 'RegistryValues.RegistryPath')
  ValueName = @('ValueName', 'ValueNames', 'RegistryValues.ValueName')
  ResourceId = @('PackageId', 'ArtifactId', 'ServiceName', 'PowerSettingGuid',
    'PowerSubgroupGuid', 'BcdElement', 'FolderName', 'TaskPath', 'TaskName',
    'ComponentId', 'ComponentIds', 'PreferenceName', 'Preference', 'Protocol', 'SchemeGuid')
}

function Get-RideSearchFields {
  <#
  .SYNOPSIS
    Return the canonical searchable field names.
  .EXAMPLE
    Get-RideSearchFields
  .OUTPUTS
    System.String. Field names in contract order.
  .NOTES
    Read-only; compatibility and version follow the module overview.
  #>
  [CmdletBinding()]
  param()
  $script:SearchFields.Keys
}

function ConvertTo-RideViewKey([string] $Value) {
  ($Value.Trim() -replace '\s+', '-').ToLowerInvariant()
}

function Get-RideCatalogViews {
  <#
  .SYNOPSIS
    Return named views and category views from the supplied catalog.
  .PARAMETER Catalog
    Data from Import-RideCatalogData; otherwise load CatalogPath as bounded data.
  .PARAMETER CatalogPath
    Literal catalog path, used only when Catalog is omitted.
  .PARAMETER IncludeProfiles
    Include the profiles view for list completion.
  .EXAMPLE
    Get-RideCatalogViews -Catalog (Import-RideCatalogData .\catalog\operations.psd1)
  .OUTPUTS
    System.String. Unique canonical view names.
  .NOTES
    Does not load profiles or inspect Windows. Version follows the module overview.
  #>
  [CmdletBinding()]
  param(
    [hashtable] $Catalog,
    [switch] $IncludeProfiles,
    [string] $CatalogPath = (Join-Path $PSScriptRoot '../catalog/operations.psd1')
  )
  if ($null -eq $Catalog) { $Catalog = Import-RideCatalogData -Path $CatalogPath -ErrorAction Stop }
  $views = @('all', 'packages', 'artifacts', 'groups', 'settings')
  if ($IncludeProfiles) { $views += 'profiles' }
  foreach ($entry in @($Catalog.Operations) + @($Catalog.Groups)) {
    $parts = @(([string]$entry.Category) -split '\s*/\s*')
    foreach ($part in $parts) {
      if (-not [string]::IsNullOrWhiteSpace($part)) { $views += ConvertTo-RideViewKey $part }
    }
    if ($parts.Count -and $parts[0]) { $views += ConvertTo-RideViewKey (($parts[0].Trim() -split '\s+')[0]) }
  }
  $views | Sort-Object -Unique
}

function Get-RideCatalogRows {
  <#
  .SYNOPSIS
    Project operations and groups into consistent discovery objects.
  .PARAMETER Catalog
    Data from Import-RideCatalogData.
  .EXAMPLE
    Get-RideCatalogRows -Catalog (Import-RideCatalogData .\catalog\operations.psd1)
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Catalog discovery rows.
  .NOTES
    Does not invoke handlers; compatibility and version follow the module overview.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Catalog)
  foreach ($entry in @($Catalog.Operations) + @($Catalog.Groups)) {
    $isGroup = -not $entry.ContainsKey('Kind')
    [pscustomobject]@{
      Type = if ($isGroup) { 'Group' } else { 'Operation' }
      Id = $entry.Id
      Name = $entry.Name
      Category = $entry.Category
      Kind = if ($isGroup) { 'Group' } else { $entry.Kind }
      Scope = if ($isGroup) { '' } else { $entry.Scope }
      RequiresAdmin = $entry.RequiresAdmin
      Actions = @($entry.Actions)
      Members = @(if ($isGroup) { $entry.Members })
      Path = ''
      Description = $entry.Description
      SupportedTargets = @(if ($entry.ContainsKey('SupportedTargets')) { $entry.SupportedTargets })
      Variants = @(if ($entry.Variants) { $entry.Variants.Keys | Sort-Object } elseif ($entry.Kind -eq 'Package') { 'installed' })
      DefaultVariant = if ($entry.DefaultVariant) { $entry.DefaultVariant } elseif ($entry.Kind -eq 'Package') { 'installed' } else { $null }
      ProductUri = $entry.ProductUri
      License = $entry.License
      LicenseUri = $entry.LicenseUri
      TermsUri = $entry.TermsUri
    } | Add-RideSettingPresentation -Operation $entry
  }
}

function Select-RideCatalogView {
  <#
  .SYNOPSIS
    Filter discovery rows using shared named or catalog category views.
  .PARAMETER Catalog
    The source catalog, used to validate category views even when results are empty.
  .PARAMETER Rows
    Discovery rows to filter.
  .PARAMETER View
    all, packages, artifacts, groups, settings, or a catalog category.
  .PARAMETER IncludeProfiles
    Permit the profiles view and profile rows for list.
  .EXAMPLE
    Select-RideCatalogView -Catalog $catalog -Rows $rows -View explorer
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Matching discovery rows.
  .NOTES
    Unknown views throw; valid views may return no rows. Version follows the module overview.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable] $Catalog,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Rows,
    [ArgumentCompleter({
      param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
      try {
        if (-not $fakeBoundParameters.ContainsKey('Catalog')) { return }
        $parameters = @{ Catalog = $fakeBoundParameters.Catalog }
        if ($fakeBoundParameters.ContainsKey('IncludeProfiles')) { $parameters.IncludeProfiles = $fakeBoundParameters.IncludeProfiles }
        foreach ($candidate in Get-RideCatalogViews @parameters) {
          if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) {
            [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate)
          }
        }
      }
      catch { }
    })]
    [string] $View = 'all',
    [switch] $IncludeProfiles
  )
  $viewKey = ConvertTo-RideViewKey $View
  $aliases = @{ package = 'packages'; artifact = 'artifacts'; group = 'groups'; setting = 'settings'; profile = 'profiles' }
  if ($aliases.ContainsKey($viewKey)) { $viewKey = $aliases[$viewKey] }
  if ($viewKey -notin @(Get-RideCatalogViews -Catalog $Catalog -IncludeProfiles:$IncludeProfiles)) {
    throw "Unknown catalog view '$View'. Press Tab after -View to discover available views."
  }
  foreach ($row in $Rows) {
    if ($row.Type -eq 'Profile' -and -not $IncludeProfiles) { continue }
    $include = switch ($viewKey) {
      'all' { $true; break }
      'profiles' { $row.Type -eq 'Profile'; break }
      'packages' { $row.Type -eq 'Operation' -and $row.Kind -eq 'Package'; break }
      'artifacts' { $row.Type -eq 'Operation' -and $row.Kind -eq 'Artifact'; break }
      'groups' { $row.Type -eq 'Group'; break }
      'settings' { $row.Type -eq 'Operation' -and $row.Kind -notin @('Package', 'Artifact'); break }
      default {
        $parts = @(([string]$row.Category) -split '\s*/\s*' | ForEach-Object { ConvertTo-RideViewKey $_ })
        $row.Type -ne 'Profile' -and ($viewKey -in $parts -or
          ($parts.Count -gt 0 -and $parts[0].StartsWith($viewKey + '-', [StringComparison]::OrdinalIgnoreCase)))
      }
    }
    if ($include) { $row }
  }
}

function Get-RideSearchValues([hashtable] $Entry, [string] $Field) {
  foreach ($source in $script:SearchFields[$Field]) {
    $parts = $source -split '\.'
    $values = @($Entry[$parts[0]])
    for ($index = 0; $index -lt $values.Count; $index++) {
      $value = $values[$index]
      if ($null -eq $value) { continue }
      $sourcePath = $parts[0]
      if ($Entry[$parts[0]] -is [array]) { $sourcePath += "[$index]" }
      if ($parts.Count -eq 2) {
        $value = $value[$parts[1]]
        $sourcePath += '.' + $parts[1]
      }
      if ($null -ne $value -and -not [string]::IsNullOrEmpty([string]$value)) {
        [pscustomobject]@{ Field = $Field; Source = $sourcePath; Value = [string]$value }
      }
    }
  }
}

function Find-RideCatalog {
  <#
  .SYNOPSIS
    Search catalog metadata using case-insensitive literal substring matching.
  .DESCRIPTION
    Returns one row per matching operation or group. Multiple fields use OR matching.
    Does not search profile files, live state, URLs, installer arguments or migration notes.
    Reads metadata without importing the engine or invoking handlers. No results is an empty collection.
  .PARAMETER Query
    Nonblank literal phrase. Wildcards, regex punctuation and backslashes are literal.
  .PARAMETER Field
    Search field names from Get-RideSearchFields; defaults to all declared search fields.
  .PARAMETER View
    Named view or category from Get-RideCatalogViews; defaults to all.
  .PARAMETER Catalog
    Resolved metadata from Get-RideCatalogContext; takes precedence over CatalogPath.
  .PARAMETER CatalogPath
    Literal catalog path; defaults to the repository catalog.
  .EXAMPLE
    Find-RideCatalog -Query desktop-folder
  .EXAMPLE
    Find-RideCatalog -Query 'ThisPCPolicy' -Field ValueName -View explorer
  .INPUTS
    None. Parameters are supplied explicitly.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Discovery rows with MatchedFields and
    Matches (Field, Source and full Value). Sorted by Type, Category, Name and Id.
  .NOTES
    Compatibility and version follow the module overview. Only the catalog is read;
    no elevation, profile loading, network access or state storage is required.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $Query,
    [ArgumentCompleter({
      param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
      try {
        foreach ($candidate in Get-RideSearchFields) {
          if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase) -and $candidate -notin $fakeBoundParameters.Field) {
            [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate)
          }
        }
      }
      catch { }
    })]
    [string[]] $Field = @(),
    [ArgumentCompleter({
      param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
      try {
        $parameters = @{}
        if ($fakeBoundParameters.ContainsKey('Catalog')) { $parameters.Catalog = $fakeBoundParameters.Catalog }
        if ($fakeBoundParameters.ContainsKey('CatalogPath')) { $parameters.CatalogPath = $fakeBoundParameters.CatalogPath }
        foreach ($candidate in Get-RideCatalogViews @parameters) {
          if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) {
            [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate)
          }
        }
      }
      catch { }
    })]
    [string] $View = 'all',
    [hashtable] $Catalog,
    [string] $CatalogPath = (Join-Path $PSScriptRoot '../catalog/operations.psd1')
  )
  if ([string]::IsNullOrWhiteSpace($Query)) { throw 'Search requires a nonblank query. Quote phrases containing spaces.' }
  $declaredFields = @(Get-RideSearchFields)
  if ($PSBoundParameters.ContainsKey('Field') -and $Field.Count -eq 0) { throw 'Select at least one search field.' }
  if (-not $Field.Count) { $Field = $declaredFields }
  foreach ($selected in $Field) {
    if ($selected -notin $declaredFields) { throw "Unknown search field '$selected'. Available fields: $($declaredFields -join ', ')." }
  }
  # Canonical order also makes repeated or differently cased field selections deterministic.
  $selectedFields = @($declaredFields | Where-Object { $_ -in $Field })
  if ($null -eq $Catalog) { $Catalog = Import-RideCatalogData -Path $CatalogPath -ErrorAction Stop }
  $entries = @{}
  foreach ($entry in @($catalog.Operations) + @($catalog.Groups)) { $entries[$entry.Id] = $entry }
  $rows = @(Select-RideCatalogView -Catalog $catalog -Rows @(Get-RideCatalogRows -Catalog $catalog) -View $View)
  $results = foreach ($row in $rows) {
    $matches = @(foreach ($selected in $selectedFields) {
      foreach ($candidate in @(Get-RideSearchValues -Entry $entries[$row.Id] -Field $selected)) {
        if ($candidate.Value.IndexOf($Query, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $candidate }
      }
    })
    if ($matches.Count) {
      $row | Add-Member -NotePropertyName MatchedFields -NotePropertyValue @($selectedFields | Where-Object { $_ -in $matches.Field })
      $row | Add-Member -NotePropertyName Matches -NotePropertyValue $matches
      # Keep interactive results compact without emitting formatting records into the pipeline.
      $row.PSObject.TypeNames.Insert(0, 'RIDE.CatalogSearchResult')
      $display = [Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet', [string[]]@('Id', 'Name', 'Kind', 'Scope', 'RequiresAdmin', 'Behavior', 'MatchedFields'))
      $row | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value ([Management.Automation.PSMemberInfo[]]@($display))
      $row
    }
  }
  $results | Sort-Object Type, Category, Name, Id
}

Export-ModuleMember -Function Get-RideSearchFields, Get-RideCatalogViews, Get-RideCatalogRows, Select-RideCatalogView, Find-RideCatalog
