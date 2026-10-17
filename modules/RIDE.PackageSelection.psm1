<#
.SYNOPSIS
  Resolve package variants and local preferences without executing packages.
.DESCRIPTION
  Keeps product IDs stable and resolves immutable planning metadata. Configuration
  is data-only; explicit selections never fall back to another distribution.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Owner: RIDE-Windows maintainers. Version: 0.3.0.
  Changelog: 0.3.0: Add data-only variant inspection without preferences or destination resolution.
    0.2.0: Resolve and retain explicit current-user EXE destinations.
    0.1.0: Add package variant and scoped configuration resolution.
#>

function Get-RidePackageConfiguration {
  <#
  .SYNOPSIS
    Read scope-specific package preferences and the machine tools root.
  .PARAMETER Scope
    Machine or User configuration scope.
  .EXAMPLE
    Get-RidePackageConfiguration -Scope Machine
  .INPUTS
    None.
  .OUTPUTS
    System.Collections.Hashtable. Validated configuration; no files are created.
  .NOTES
    Compatibility and version follow the module overview.
  #>
  [CmdletBinding()]
  param([ValidateSet('Machine', 'User')][string] $Scope = 'Machine')
  $root = if ($Scope -eq 'Machine') { [Environment]::GetFolderPath('CommonApplicationData') } else { [Environment]::GetFolderPath('LocalApplicationData') }
  $path = Join-Path $root 'RIDE/configuration.psd1'
  $config = @{}
  if (Test-Path -LiteralPath $path -PathType Leaf) {
    $file = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($file.Length -gt 65536) { throw 'RIDE local configuration exceeds 64 KiB.' }
    $config = Import-PowerShellDataFile -LiteralPath $path -ErrorAction Stop
    if ($config.SchemaVersion -ne 1) { throw "Unsupported local configuration schema: $path" }
    foreach ($key in $config.Keys) {
      if ($key -notin @('SchemaVersion', 'ToolsDirectory', 'PackageVariantPreference')) { throw "Unknown local configuration field: $key" }
    }
    if ($Scope -eq 'User' -and $config.ContainsKey('ToolsDirectory')) { throw 'ToolsDirectory belongs in machine configuration.' }
    if ($config.PackageVariantPreference -and $config.PackageVariantPreference -notmatch '^[a-z][a-z0-9-]*$') { throw 'Invalid PackageVariantPreference.' }
  }
  if ($Scope -eq 'Machine' -and -not $config.ToolsDirectory) { $config.ToolsDirectory = Join-Path $env:SystemDrive 'Tools' }
  if ($config.ToolsDirectory) {
    $path = [string]$config.ToolsDirectory
    if ($path -notmatch '^[A-Za-z]:[\\/]' -or $path -match '[*?\x00-\x1f]' -or $path -match '(^|[\\/])\.\.([\\/]|$)') { throw 'ToolsDirectory must be an absolute local path without wildcards or traversal.' }
    $config.ToolsDirectory = [IO.Path]::GetFullPath($path).TrimEnd('\', '/')
    if ($config.ToolsDirectory -eq [IO.Path]::GetPathRoot($path).TrimEnd('\', '/')) { throw 'ToolsDirectory cannot be a volume root.' }
  }
  $config
}

function Resolve-RidePackageSelection {
  <#
  .SYNOPSIS
    Resolve a declared package variant into handler metadata.
  .PARAMETER Operation
    Catalog package record.
  .PARAMETER Variant
    Optional explicit variant key. Unsupported explicit choices fail.
  .PARAMETER IgnorePreferences
    Resolve the catalog default without reading local variant preferences.
  .PARAMETER MetadataOnly
    Inspect supplied variant metadata only, ignoring preferences and destination
    resolution. Does not read local configuration or environment paths. The result
    is not an operational selection and must not be passed to an installer.
  .EXAMPLE
    Resolve-RidePackageSelection -Operation $package -Variant portable
  .INPUTS
    None.
  .OUTPUTS
    System.Collections.Hashtable. A copy with the selected variant and destination.
  .NOTES
    Read-only. Existing flat package records retain their default behavior.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation,
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $op=$fakeBoundParameters.Operation
        if($op.Kind -ne 'Package'){return}
        $choices=if($op.SelectedVariant){@($op.SelectedVariant)}elseif($op.Variants){@($op.Variants.Keys)}else{@('installed')}
        if($choices.Count -gt 128){return}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $prefix=([string]$wordToComplete).Trim("'",'"')
        foreach($choice in $choices){if($choice -is [string] -and $choice.Length -le 128 -and $choice -cmatch '^[a-z][a-z0-9-]*$' -and $choice.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($choice)){[Management.Automation.CompletionResult]::new($choice,$choice,'ParameterValue',$choice)}}
      }catch{return}
    })][string] $Variant, [switch] $IgnorePreferences, [switch] $MetadataOnly)
  if ($Operation.Kind -ne 'Package') { if ($Variant) { throw 'Variant requires a package ID.' }; return $Operation }
  if ($Operation.SelectedVariant) {
    if ($Variant -and $Variant -ne $Operation.SelectedVariant) { throw 'A resolved package selection cannot be changed.' }
    return $Operation
  }
  $result = $Operation.Clone()
  $default = if ($Operation.DefaultVariant) { [string]$Operation.DefaultVariant } else { 'installed' }
  $chosen = if ($Variant) { $Variant } else { $default }
  if (-not $Variant -and -not $IgnorePreferences -and -not $MetadataOnly) {
    $preferenceScope = if ($Operation.Scope) { $Operation.Scope } else { 'Machine' }
    $preference = (Get-RidePackageConfiguration -Scope $preferenceScope).PackageVariantPreference
    if ($preference) {
      if (($Operation.Variants -and $Operation.Variants.ContainsKey($preference)) -or (-not $Operation.Variants -and $preference -eq 'installed')) { $chosen = $preference }
      else { $result.SelectionNote = "Preference '$preference' is unavailable; using '$default'." }
    }
  }
  if ($Operation.Variants) {
    if (-not $Operation.Variants.ContainsKey($chosen)) { throw "Unsupported variant '$chosen' for '$($Operation.Id)'." }
    foreach ($key in $Operation.Variants[$chosen].Keys) { $result[$key] = $Operation.Variants[$chosen][$key] }
  } elseif ($chosen -ne 'installed') { throw "Unsupported variant '$chosen' for '$($Operation.Id)'." }
  $result.SelectedVariant = $chosen
  $result.Remove('Variants')
  if ($MetadataOnly) { return $result }
  if ($result.InstallerType -eq 'Portable') {
    $result.ResolvedToolsDirectory = (Get-RidePackageConfiguration -Scope Machine).ToolsDirectory
    $result.InstallDirectory = Join-Path $result.ResolvedToolsDirectory $result.PackageId
  }
  if ($result.LocalAppDataInstallDirectory) {
    $name=[string]$result.LocalAppDataInstallDirectory
    if ($result.Scope -ne 'User' -or $result.InstallerType -ne 'Exe' -or $name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,79}$' -or $name.EndsWith('.') -or $name.EndsWith(' ')) { throw 'Invalid current-user installation directory.' }
    $result.InstallDirectory=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Programs/'+$name)
    if ($result.InstallDirectory -match '["\r\n]') { throw 'Unsafe current-user installation path.' }
    $result.InstallerArguments=([string]$result.InstallerArguments).Replace('{InstallDirectory}', $result.InstallDirectory)
  }
  $result
}

Export-ModuleMember -Function Get-RidePackageConfiguration, Resolve-RidePackageSelection
