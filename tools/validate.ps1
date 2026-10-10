<#
.SYNOPSIS
  Validate RIDE catalog, profiles, PowerShell syntax, and generated documentation.

.DESCRIPTION
  Checks catalog schema, declared operation lifecycle and references, artifact observations, profile
  selections, and script parsing. Invokes the catalog generator in Check mode. Throws aggregated
  validation failures; does not invoke handlers or installers.

.PARAMETER Root
  Repository root; defaults to the parent of the tools directory.

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
  Version: 0.5.0
  Changelog:
  - 0.5.0: Validate publisher license references and keep local reviews out of the catalog.
  - 0.4.0: Validate nullable registry default existence for image-dependent values.
  - 0.3.0: Validate the desktop Shell folder metadata and profile states.
  - 0.2.0: Validate larger catalogs, MSI lifecycle metadata and prerequisites.
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

#>


[CmdletBinding()]
param([string] $Root = '',
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.5.0'
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

$ids = @{}
foreach ($operation in $catalog.Operations) {
  foreach ($localField in @('LicenseReviewStatus', 'DistributionNotes', 'LicenseReviewedAt', 'ReviewOwner', 'ReviewedVersion')) {
    if ($operation.ContainsKey($localField)) { Add-Error "User/company license reviews belong in local storage, not the catalog: $($operation.Id) / $localField" }
  }
  if ($operation.Kind -in @('Package', 'Artifact')) {
    if ([string]::IsNullOrWhiteSpace([string]$operation.License)) { Add-Error "Download operation requires a license summary (Unknown when unavailable): $($operation.Id)" }
    if (-not [Uri]::IsWellFormedUriString([string]$operation.LicenseUri, [UriKind]::Absolute) -or ([Uri]$operation.LicenseUri).Scheme -ne 'https') {
      Add-Error "Download operation requires an absolute HTTPS license URI: $($operation.Id)"
    }
    if ($operation.ContainsKey('TermsUri') -and (-not [Uri]::IsWellFormedUriString([string]$operation.TermsUri, [UriKind]::Absolute) -or ([Uri]$operation.TermsUri).Scheme -ne 'https')) {
      Add-Error "Additional terms must use an absolute HTTPS URI: $($operation.Id)"
    }
  }
  foreach ($field in @('Id', 'Name', 'Kind', 'Category', 'Description', 'SupportedTargets', 'Scope', 'RequiresAdmin', 'Actions', 'Handler', 'Rollback')) {
    if (-not $operation.ContainsKey($field)) { Add-Error "Operation is missing required field '$field': $($operation.Id)" }
  }
  if ($operation.Id -notmatch '^[a-z][a-z0-9.-]+$') { Add-Error "Invalid operation ID: $($operation.Id)" }
  if ($ids.ContainsKey($operation.Id)) { Add-Error "Duplicate catalog ID: $($operation.Id)" }
  $ids[$operation.Id] = $true
  if ($operation.Scope -notin @('Machine', 'User')) { Add-Error "Invalid scope for $($operation.Id): $($operation.Scope)" }
  if (@($operation.SupportedTargets).Count -eq 0) { Add-Error "No supported target declared for $($operation.Id)" }
  if (-not $operation.ContainsKey('TargetDefaults')) {
    Add-Error "Operation is missing target defaults: $($operation.Id)"
    $targetDefaults = @{}
  }
  else {
    $targetDefaults = $operation.TargetDefaults
  }
  foreach ($target in $operation.SupportedTargets) {
    if (-not $targetDefaults.ContainsKey($target)) {
      Add-Error "Operation '$($operation.Id)' is missing defaults for '$target'."
      continue
    }
    $defaults = $targetDefaults[$target]
    if (-not $defaults.ContainsKey('EffectiveDefault')) { Add-Error "Operation '$($operation.Id)' is missing an effective default for '$target'." }
    if ($operation.Kind -eq 'RegistryValue' -and -not $defaults.ContainsKey('DefaultValueExists')) {
      Add-Error "Operation '$($operation.Id)' is missing literal default existence for '$target'."
    }
    if ($operation.Kind -eq 'RegistryValue' -and $defaults.ContainsKey('DefaultValueExists')) {
      if ($null -ne $defaults.DefaultValueExists -and $defaults.DefaultValueExists -isnot [bool]) {
        Add-Error "Registry default existence must be a Boolean or null: $($operation.Id) ($target)."
      }
      if (-not $defaults.ContainsKey('DefaultValue') -or ($null -eq $defaults.DefaultValueExists -and $null -ne $defaults.DefaultValue)) {
        Add-Error "Registry defaults require DefaultValue; platform-defined defaults must use null: $($operation.Id) ($target)."
      }
    }
  if ($operation.Kind -in @('Package', 'Artifact', 'DefenderExclusion') -and -not $defaults.ContainsKey('DefaultValue')) {
      Add-Error "Operation '$($operation.Id)' is missing a literal default for '$target'."
    }
    if ($operation.Kind -eq 'RegistryKeySet' -and -not $defaults.ContainsKey('DefaultValue')) {
      Add-Error "Registry key-set operation '$($operation.Id)' is missing a literal default for '$target'."
    }
    if ($operation.Kind -eq 'WindowsService' -and -not $defaults.ContainsKey('DefaultValue')) {
      Add-Error "Operation '$($operation.Id)' is missing a literal service default for '$target'."
    }
    if ($operation.Kind -eq 'BackgroundAppOverrides' -and -not $defaults.ContainsKey('DefaultValue')) {
      Add-Error "Operation '$($operation.Id)' is missing a literal override default for '$target'."
    }
    if ($operation.Kind -eq 'BootConfiguration' -and -not $defaults.ContainsKey('DefaultValue')) {
      Add-Error "Operation '$($operation.Id)' is missing a literal boot configuration default for '$target'."
    }
    if ($operation.Kind -eq 'NetworkProfile' -and -not $defaults.ContainsKey('DefaultValue')) {
      Add-Error "Operation '$($operation.Id)' is missing a network-profile default for '$target'."
    }
    if ($operation.Kind -eq 'PowerSetting' -and -not $defaults.ContainsKey('DefaultValue')) {
      Add-Error "Operation '$($operation.Id)' is missing a power-setting default for '$target'."
    }
  }
  if ($operation.Kind -eq 'RegistryValue') {
    foreach ($field in @('RegistryPath', 'ValueName', 'ValueType', 'States', 'BaselineState')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Registry operation is missing '$field': $($operation.Id)" }
    }
    if (-not $operation.ContainsKey('DocumentationUri')) { Add-Error "Registry operation is missing Microsoft documentation URI: $($operation.Id)" }
    elseif (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -notin @('learn.microsoft.com', 'support.microsoft.com')) {
      Add-Error "Registry operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
    }
    if (-not $operation.States.ContainsKey($operation.BaselineState)) { Add-Error "Invalid baseline state for $($operation.Id)" }
    if ($operation.Handler -ne 'RegistryValue') { Add-Error "No matching handler for $($operation.Id)" }
  }
  elseif ($operation.Kind -eq 'Package') {
    if ($operation.InstallerType -notin @('Exe', 'Msi', 'SysmonZip')) { Add-Error "Unsupported installer type: $($operation.Id)" }
    if ($operation.InstallerType -eq 'Msi' -and ($operation.InstallerArguments -notmatch '/qn' -or $operation.InstallerArguments -notmatch '/norestart')) { Add-Error "MSI packages require quiet, no-restart arguments: $($operation.Id)" }
    if ($operation.PrerequisitePackageId) {
      if ($operation.PrerequisitePackageId -notin @($catalog.Operations | Where-Object Kind -eq 'Package' | ForEach-Object Id)) { Add-Error "Unknown package prerequisite: $($operation.Id)" }
      if (-not $operation.PrerequisiteProgramFilesExecutable -or [IO.Path]::IsPathRooted($operation.PrerequisiteProgramFilesExecutable) -or $operation.PrerequisiteProgramFilesExecutable -match '(^|[\\/])\.\.([\\/]|$)|["\r\n:*?]') { Add-Error "Invalid prerequisite executable: $($operation.Id)" }
    }
    if ($operation.Handler -ne 'Package') { Add-Error "No matching handler for $($operation.Id)" }
    foreach ($field in @('PackageId', 'InstallerType', 'DownloadUri', 'InstallerArguments', 'UninstallerArguments', 'DisplayNamePattern')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Package operation is missing '$field': $($operation.Id)" }
    }
    if (-not $operation.ContainsKey('ProductUri')) { Add-Error "Package operation is missing product information URI: $($operation.Id)" }
    elseif (-not [Uri]::IsWellFormedUriString([string]$operation.ProductUri, [UriKind]::Absolute) -or ([Uri]$operation.ProductUri).Scheme -ne 'https') {
      Add-Error "Package operation must use an absolute HTTPS product URI: $($operation.Id)"
    }
    if ('Install' -notin $operation.Actions -or 'Uninstall' -notin $operation.Actions) { Add-Error "Package lifecycle must include install and uninstall: $($operation.Id)" }
    if ('Download' -in $operation.Actions) {
      foreach ($field in @('DownloadProvider', 'AssetPattern', 'Architecture')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Downloadable package is missing '$field': $($operation.Id)" }
      }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DownloadUri, [UriKind]::Absolute) -or ([Uri]$operation.DownloadUri).Scheme -ne 'https') {
        Add-Error "Downloadable package must use an absolute HTTPS source URI: $($operation.Id)"
      }
      if ($operation.DownloadProvider -eq 'GitHubReleaseApi') {
        if ([Uri]::IsWellFormedUriString([string]$operation.DownloadUri, [UriKind]::Absolute) -and ([Uri]$operation.DownloadUri).Host -ne 'api.github.com') { Add-Error "GitHub release API provider must use api.github.com: $($operation.Id)" }
      }
      elseif ($operation.DownloadProvider -eq 'SysinternalsSysmonPage') {
        if (-not $operation.ContainsKey('VersionUri') -or -not [Uri]::IsWellFormedUriString([string]$operation.VersionUri, [UriKind]::Absolute) -or ([Uri]$operation.VersionUri).Host -ne 'learn.microsoft.com') { Add-Error "Sysmon latest provider must resolve the version from Microsoft Learn: $($operation.Id)" }
        if (([Uri]$operation.DownloadUri).Host -ne 'download.sysinternals.com' -or $operation.AssetName -ne 'Sysmon.zip' -or $operation.InstallerType -ne 'SysmonZip') { Add-Error "Invalid Microsoft Sysmon archive metadata: $($operation.Id)" }
      }
      else { Add-Error "Unsupported package download provider '$($operation.DownloadProvider)': $($operation.Id)" }
      if (-not $operation.AssetPattern -or $operation.Architecture -notin @('x64', 'x86', 'arm64')) { Add-Error "Invalid package asset pattern or architecture: $($operation.Id)" }
    }
  }
  elseif ($operation.Kind -eq 'Artifact') {
    if ($operation.Handler -ne 'Artifact') { Add-Error "No matching handler for $($operation.Id)" }
    foreach ($field in @('ArtifactId', 'DownloadUri', 'DownloadProvider', 'Repository', 'AssetPath', 'Architecture', 'ProductUri')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Download-only artifact is missing '$field': $($operation.Id)" }
    }
    if (@($operation.Actions).Count -ne 1 -or 'Download' -notin $operation.Actions) { Add-Error "Download-only artifact must expose only Download: $($operation.Id)" }
    if ($operation.DownloadProvider -ne 'GitHubFileCommitApi' -or ([Uri]$operation.DownloadUri).Host -ne 'api.github.com') { Add-Error "Unsupported download-only artifact provider or URI: $($operation.Id)" }
    if (-not [Uri]::IsWellFormedUriString([string]$operation.ProductUri, [UriKind]::Absolute) -or ([Uri]$operation.ProductUri).Scheme -ne 'https') { Add-Error "Artifact product URI must be an absolute HTTPS URI: $($operation.Id)" }
    if ($operation.Architecture -notin @('neutral', 'x64', 'x86', 'arm64')) { Add-Error "Invalid artifact architecture: $($operation.Id)" }
  }
  elseif ($operation.Kind -eq 'DefenderExclusion') {
    if ($operation.Handler -ne 'DefenderExclusion') { Add-Error "No matching handler for $($operation.Id)" }
    if ($operation.PathResolver -notin @('ToolsDirectory', 'BootstrapDirectory')) { Add-Error "Invalid Defender exclusion path resolver: $($operation.Id)" }
    if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Defender exclusion lifecycle is incomplete: $($operation.Id)" }
    foreach ($target in $operation.SupportedTargets) {
      if ($operation.TargetDefaults[$target].DefaultValue -notin @('Present', 'Absent')) { Add-Error "Invalid Defender exclusion default for $($operation.Id) on '$target'." }
    }
  }
  elseif ($operation.Kind -eq 'WindowsService') {
    if ($operation.Handler -ne 'WindowsService') { Add-Error "No matching handler for $($operation.Id)" }
    foreach ($field in @('ServiceName', 'States', 'DocumentationUri')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Windows service operation is missing '$field': $($operation.Id)" }
    }
    if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
      Add-Error "Windows service operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
    }
    foreach ($stateName in $operation.States.Keys) {
      $state = $operation.States[$stateName]
      if ($state.StartupType -notin @('Automatic', 'Manual', 'Disabled') -or $state.Status -notin @('Running', 'Stopped')) {
        Add-Error "Invalid startup type or running state for '$($operation.Id)' state '$stateName'."
      }
    }
    if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Windows service lifecycle is incomplete: $($operation.Id)" }
  }
  elseif ($operation.Kind -eq 'BackgroundAppOverrides') {
    if ($operation.Handler -ne 'BackgroundAppOverrides') { Add-Error "No matching handler for $($operation.Id)" }
    foreach ($field in @('RegistryPath', 'ValueNames', 'States', 'DocumentationUri')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Background app override operation is missing '$field': $($operation.Id)" }
    }
    if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
      Add-Error "Background app override operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
    }
    if ('Reset' -notin $operation.States.Keys) { Add-Error "Background app override operation must declare Reset: $($operation.Id)" }
    if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Background app override lifecycle is incomplete: $($operation.Id)" }
  }
  elseif ($operation.Kind -eq 'BootConfiguration') {
    if ($operation.Handler -ne 'BootConfiguration') { Add-Error "No matching handler for $($operation.Id)" }
    foreach ($field in @('BcdElement', 'States', 'BaselineState', 'RestartRequired', 'DocumentationUri')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Boot configuration operation is missing '$field': $($operation.Id)" }
    }
    if ($operation.BcdElement -notin @('bootmenupolicy', 'nx')) { Add-Error "Unsupported BCD element for '$($operation.Id)'." }
    if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
      Add-Error "Boot configuration operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
    }
    if (-not $operation.States.ContainsKey($operation.BaselineState)) { Add-Error "Invalid baseline state for $($operation.Id)" }
    if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Boot configuration lifecycle is incomplete: $($operation.Id)" }
  }
  elseif ($operation.Kind -eq 'NetworkProfile') {
    if ($operation.Handler -ne 'NetworkProfile') { Add-Error "No matching handler for $($operation.Id)" }
    foreach ($field in @('States', 'BaselineState', 'DocumentationUri')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Network profile operation is missing '$field': $($operation.Id)" }
    }
    if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
      Add-Error "Network profile operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
    }
    if (-not $operation.States.ContainsKey($operation.BaselineState)) { Add-Error "Invalid baseline state for $($operation.Id)" }
    foreach ($stateName in $operation.States.Keys) {
      if ($operation.States[$stateName] -notin @('Private', 'Public')) { Add-Error "Invalid network category in '$($operation.Id)' state '$stateName'." }
    }
    if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Network profile lifecycle is incomplete: $($operation.Id)" }
  }
  elseif ($operation.Kind -eq 'RegistryKeySet') {
    if ($operation.Handler -ne 'RegistryKeySet') { Add-Error "No matching handler for $($operation.Id)" }
    foreach ($field in @('RegistryPaths', 'States', 'BaselineState', 'DocumentationUri')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Registry key-set operation is missing '$field': $($operation.Id)" }
    }
    if (@($operation.RegistryPaths).Count -eq 0) { Add-Error "Registry key-set operation has no paths: $($operation.Id)" }
    foreach ($path in $operation.RegistryPaths) {
      if ([string]$path -notmatch '^HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\\{[0-9A-Fa-f-]{36}\}$') {
        Add-Error "Registry key-set path is outside the supported This PC Shell namespace roots: $($operation.Id)"
      }
    }
    if (@($operation.RegistryPaths | Select-Object -Unique).Count -ne @($operation.RegistryPaths).Count) { Add-Error "Registry key-set paths must be unique: $($operation.Id)" }
    if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
      Add-Error "Registry key-set operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
    }
    if (-not $operation.States.ContainsKey($operation.BaselineState)) { Add-Error "Invalid baseline state for $($operation.Id)" }
    foreach ($stateName in $operation.States.Keys) {
      if ($operation.States[$stateName] -notin @('Present', 'Absent')) { Add-Error "Invalid registry key-set value in '$($operation.Id)' state '$stateName'." }
    }
    if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Registry key-set lifecycle is incomplete: $($operation.Id)" }
  }
  elseif ($operation.Kind -eq 'PowerSetting') {
    if ($operation.Handler -ne 'PowerSetting') { Add-Error "No matching handler for $($operation.Id)" }
    foreach ($field in @('PowerSubgroupGuid', 'PowerSettingGuid', 'PowerIndex', 'States', 'DocumentationUri')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Power setting operation is missing '$field': $($operation.Id)" }
    }
    foreach ($field in @('PowerSubgroupGuid', 'PowerSettingGuid')) {
      if ([string]$operation.$field -notmatch '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { Add-Error "Invalid power setting GUID '$field': $($operation.Id)" }
    }
    if ($operation.PowerIndex -notin @('AC', 'DC')) { Add-Error "Power setting index must be AC or DC: $($operation.Id)" }
    if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
      Add-Error "Power setting operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
    }
    if (@($operation.States.Keys).Count -lt 2 -or @($operation.States.Values | Select-Object -Unique).Count -ne @($operation.States.Values).Count) { Add-Error "Power setting states must map to unique values: $($operation.Id)" }
    foreach ($value in $operation.States.Values) { if ($value -notin @(0, 1)) { Add-Error "Unsupported lid-close index in '$($operation.Id)': $value" } }
    foreach ($target in $operation.SupportedTargets) { if ($operation.TargetDefaults[$target].DefaultValue -ne 'Platform-defined') { Add-Error "Power setting default must remain platform-defined: $($operation.Id)" } }
    if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Power setting lifecycle is incomplete: $($operation.Id)" }
    if ($operation.ContainsKey('BaselineState')) { Add-Error "Power setting must not invent a RIDE baseline: $($operation.Id)" }
  }
  elseif ($operation.Kind -eq 'ShellFolder') {
    if ($operation.Handler -ne 'ShellFolder') { Add-Error "No matching handler for $($operation.Id)" }
    if ($operation.Scope -ne 'User' -or $operation.RequiresAdmin -ne $false -or $operation.PathResolver -ne 'CurrentUserDesktop') { Add-Error "Shell folder must use the current-user desktop: $($operation.Id)" }
    if ($operation.FolderName -cne 'GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}') { Add-Error "Unsupported Shell folder name: $($operation.Id)" }
    if (-not $operation.States -or @($operation.States.Keys).Count -ne 2 -or $operation.States.Present -cne 'Present' -or $operation.States.Absent -cne 'Absent' -or $operation.BaselineState -cne 'Absent') { Add-Error "Shell folder must declare Present/Absent and baseline Absent: $($operation.Id)" }
    if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') { Add-Error "Shell folder requires Microsoft documentation: $($operation.Id)" }
    foreach ($target in $operation.SupportedTargets) { if ($operation.TargetDefaults[$target].DefaultValue -cne 'Absent') { Add-Error "Shell folder default must be Absent: $($operation.Id)" } }
    foreach ($action in @('Get', 'Test', 'Set', 'Restore')) { if ($action -notin $operation.Actions) { Add-Error "Shell folder lifecycle is missing '$action': $($operation.Id)" } }
    if ($operation.Rollback -ne 'Exact') { Add-Error "Shell folder requires exact restore: $($operation.Id)" }
  }
  else { Add-Error "Unknown operation kind '$($operation.Kind)': $($operation.Id)" }
}

foreach ($group in $catalog.Groups) {
  if ($ids.ContainsKey($group.Id)) { Add-Error "Duplicate catalog ID: $($group.Id)" }
  $ids[$group.Id] = $true
  if (@($group.Members).Count -eq 0) { Add-Error "Group has no members: $($group.Id)" }
  foreach ($member in $group.Members) {
    if (-not ($catalog.Operations | Where-Object { $_.Id -eq $member })) { Add-Error "Unknown member '$member' in group '$($group.Id)'" }
  }
}

foreach ($profileFile in $profilePaths) {
  $profile = Import-PowerShellDataFile -Path $profileFile.FullName
  if ($profile.SchemaVersion -ne 1) { Add-Error "$($profileFile.Name) must declare SchemaVersion 1." }
  if (-not $profile.Operations) { Add-Error "$($profileFile.Name) has no selected operations." }
  $profileIds = @{}
  foreach ($selection in $profile.Operations) {
    if ($profileIds.ContainsKey($selection.Id)) { Add-Error "$($profileFile.Name) selects '$($selection.Id)' more than once." }
    $profileIds[$selection.Id] = $true
    if (-not $ids.ContainsKey($selection.Id)) { Add-Error "$($profileFile.Name) references unknown ID '$($selection.Id)'"; continue }
    $operation = $catalog.Operations | Where-Object { $_.Id -eq $selection.Id } | Select-Object -First 1
    $group = $catalog.Groups | Where-Object { $_.Id -eq $selection.Id } | Select-Object -First 1
    if ($operation -and $operation.Kind -eq 'RegistryValue' -and $selection.State -ne 'Baseline' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid state for '$($selection.Id)'" }
    if ($operation -and $operation.Kind -eq 'Artifact') { Add-Error "$($profileFile.Name) cannot select download-only artifact '$($selection.Id)' as a desired Windows state." }
    if ($operation -and $operation.Kind -eq 'WindowsService' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid service state for '$($selection.Id)'" }
    if ($operation -and $operation.Kind -eq 'BackgroundAppOverrides' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid background app state for '$($selection.Id)'" }
    if ($operation -and $operation.Kind -eq 'BootConfiguration' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid boot configuration state for '$($selection.Id)'" }
    if ($operation -and $operation.Kind -eq 'NetworkProfile' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid network-profile state for '$($selection.Id)'" }
    if ($operation -and $operation.Kind -eq 'RegistryKeySet' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid registry key-set state for '$($selection.Id)'" }
    if ($operation -and $operation.Kind -eq 'PowerSetting' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid power-setting state for '$($selection.Id)'" }
    if ($operation -and $operation.Kind -eq 'ShellFolder' -and $selection.State -ne 'Baseline' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid Shell folder state for '$($selection.Id)'" }
    if ((($operation -and $operation.Kind -in @('Package', 'DefenderExclusion')) -or $group) -and $selection.State -notin @('Present', 'Absent')) { Add-Error "$($profileFile.Name) must use Present or Absent for '$($selection.Id)'" }
  }
}

$powershellFiles = Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object {
  $_.Extension -in @('.ps1', '.psm1') -and $_.FullName -notmatch '[\\/](\.git|\.vs)[\\/]'
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
