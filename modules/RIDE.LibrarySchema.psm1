<#
.SYNOPSIS
  Declare the supported choices for custom-library API 1.
.DESCRIPTION
  Shares authoring choices with metadata validation. Reads catalog targets only;
  never imports the operational engine, queries Windows or invokes handlers.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Owner: RIDE-Windows maintainers. Version: 0.3.0.
  Changelog: 0.3.0: Add coordinated registry values and scope-explicit HKCR authoring.
    0.2.0: Expose optional ZIP packaging independently of installer type.
    0.1.0: Share API 1 choices with the guided authoring helper.
#>


Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1') -ErrorAction Stop

function Get-RideLibraryAuthoringOptions {
  <#
  .SYNOPSIS
    Return valid API 1 choices for custom-library authors.
  .DESCRIPTION
    Enumerates schema choices and target names from the built-in catalog.
    Target names are authoring choices, not evidence that a new operation works.
  .PARAMETER Root
    RIDE checkout containing catalog/operations.psd1.
  .EXAMPLE
    Get-RideLibraryAuthoringOptions
  .INPUTS
    None.
  .OUTPUTS
    System.Collections.Hashtable. Named arrays of supported choices.
  .NOTES
    Read-only. Version and compatibility follow the module overview.
  #>
  [CmdletBinding()]
  param([string] $Root = (Split-Path -Parent $PSScriptRoot))
  $catalog = Import-RideCatalogData -Path (Join-Path $Root 'catalog/operations.psd1')
  @{
    Kinds = @('Package', 'RegistryValue', 'RegistryValueSet')
    InstallerTypes = @('Exe', 'Msi')
    ArchiveTypes = @('None', 'Zip')
    RegistryValueTypes = @('String', 'ExpandString', 'Binary', 'DWord', 'QWord')
    RegistryValueSetTypes = @('String', 'DWord')
    Scopes = @('User', 'Machine')
    Architectures = @('x64', 'x86', 'arm64')
    DownloadProviders = @('DirectHttps', 'GitHubReleaseApi')
    SupportedTargets = @($catalog.Operations.SupportedTargets | Sort-Object -Unique)
  }
}

function ConvertTo-RideLibraryRegistryPath {
  <#
  .SYNOPSIS
    Normalize an author-supplied registry path to an explicit user/machine root.
  .DESCRIPTION
    HKCR is mapped to Software\Classes in the selected scope. Accepts short
    PowerShell roots and long .reg roots. No registry access or drive creation.
  .PARAMETER Path
    Registry key path; a literal asterisk such as the all-files class is allowed.
  .PARAMETER Scope
    User maps HKCR to HKCU; Machine maps it to HKLM. Other scope roots are refused.
  .EXAMPLE
    ConvertTo-RideLibraryRegistryPath 'HKEY_CLASSES_ROOT\*\shell\Example' -Scope User
  .INPUTS
    None.
  .OUTPUTS
    System.String. Explicit HKCU or HKLM path.
  .NOTES
    Read-only. Version and compatibility follow the module overview.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][ValidateSet('User', 'Machine')][string] $Scope)
  if ($Path -notmatch '^(?:Registry::)?(?<Hive>HKCR|HKCU|HKLM|HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE):?\\(?<Key>.+)$' -or
      $Path -match '[\x00-\x1f/]|(^|\\)\.{1,2}(\\|$)') { throw 'Use a complete HKCU, HKLM or HKCR key path without traversal or control characters.' }
  $hive = $Matches.Hive; $key = $Matches.Key
  $root = if ($Scope -eq 'User') { 'HKCU' } else { 'HKLM' }
  if ($hive -in @('HKCR', 'HKEY_CLASSES_ROOT')) { return ($root + ':\Software\Classes\' + $key) }
  $actualRoot = if ($hive -in @('HKCU', 'HKEY_CURRENT_USER')) { 'HKCU' } else { 'HKLM' }
  if ($actualRoot -ne $root) { throw "Registry path conflicts with $Scope scope; use ${root}:\ or HKCR." }
  $root + ':\' + $key
}

Export-ModuleMember -Function Get-RideLibraryAuthoringOptions, ConvertTo-RideLibraryRegistryPath
