<#
.SYNOPSIS
  Load the RIDE catalog, build plans, and manage operation lifecycles.

.DESCRIPTION
  Imports focused handlers, expands profiles/groups, checks supported targets, inspects state,
  executes ShouldProcess-gated plans, captures per-scope pre-change snapshots/manifests, and
  restores saved runs. Installed-package restoration may use the latest release rather than the exact previous
  version. Import establishes paths and command definitions; handlers are invoked only by explicit
  commands.

.EXAMPLE
  Import-Module .\modules\RIDE.Engine.psm1

.EXAMPLE
  Get-RideCatalog

.EXAMPLE
  Get-RideProfile

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return catalog/profile objects, plan/status records, formatted
  views, or lifecycle progress strings.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Windows-native PowerShell and the focused modules; target/elevation requirements
  are checked per catalog operation.
  File/environment inputs: catalog/operations.psd1, profiles/*.psd1, ProgramData/RIDE/State for
  machine scope, LocalApplicationData/RIDE/State for user scope, artifact observations,
  and explicitly selected local library manifests/catalogs/profiles.
  Recovery: Restore-RideRun recovers captured settings/presence. Read catalog rollback limits before
  applying packages or grouped changes.
  Author: RIDE-Windows maintainers.
  Version: 0.20.4
  Changelog:
    0.20.4: Bind Defender exclusion writes and versioned recovery to captured paths.
    0.20.3: Preserve unsigned power indexes in inspection and marked recovery snapshots.
    0.20.2: Describe user-bin startup PATH separately from profile colors.
    0.20.1: Inspect Store app registrations and refuse implicit profile/package routing.
    0.20.0: Add explicit GitHub PAT selection and credential-safe acceptance boundaries.
    - 0.19.0: Add local SAM maximum-age capture, day states and focused recovery.
    - 0.18.2: Expose read-only dependency observations for guarded service details.
    - 0.18.1: Present preserved registry components as keep current in plans and status.
    - 0.18.0: Add separately owned power-plan copies with bounded compensating recovery.
    - 0.17.1: Use the registry reader's key-existence capture in saved scalar snapshots.
    - 0.17.0: Display separate read-only policy conflicts and enforce declared minimum builds.
    - 0.16.0: Integrate pending local/effective firewall profiles and coordinated enable-all recovery.
    - 0.15.0: Match/display service delay and capture versioned SCM/literal recovery state.
    - 0.14.0: Integrate reversible per-runtime PowerShell profile settings.
    - 0.13.1: Reload the library resolver when importing the engine.
    - 0.13.0: Enforce saved current-user package execution context before writes.
    0.12.0: Present setting scope, policy behavior, GUI effect and prerequisites consistently.
    0.11.0: Resolve package variants, record artifact evidence and restore schema-3 selections.
  - 0.10.0: Retain optional author-supplied recovery instructions with snapshots.
  - 0.9.0: Resolve explicit metadata libraries and preflight their saved-run recovery identity.
  - 0.8.0: Manage existing task, adapter, network, Defender, SMB, sound and power-scheme settings.
  - 0.7.0: Share catalog discovery rows and view selection with literal search.
  - 0.6.0: Coordinate registry value sets with complete snapshots and saved-run recovery.
  - 0.5.0: Include publisher and license references in consistent discovery objects.
  - 0.4.0: Report image-dependent registry defaults without assuming value absence.
    Enforce elevation for singleton machine plans on Windows PowerShell 5.1.
  - 0.3.0: Add desktop Shell folder plans, snapshots, status and exact restore.
  - 0.2.0: Load larger catalogs through the bounded data-only reader.
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

.LINK
  docs/OPERATIONS.md

.LINK
  docs/models/script-repository-model.md

#>


$script:ModuleVersion = '0.20.4'

$script:RideRoot = Split-Path -Parent $PSScriptRoot
$script:RideCatalogPath = Join-Path $script:RideRoot 'catalog/operations.psd1'
Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE.Libraries.psm1') -Force -ErrorAction Stop
$script:RideLibraryContext = $null
Import-Module (Join-Path $PSScriptRoot 'RIDE.Discovery.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.SettingPresentation.psm1') -ErrorAction Stop
$script:RideSettingsModule = Join-Path $PSScriptRoot 'RIDE-Settings.psm1'
$script:RidePackagesModule = Join-Path $PSScriptRoot 'RIDE-Packages.psm1'
$script:RideDefenderModule = Join-Path $PSScriptRoot 'RIDE-Defender.psm1'
$script:RideServicesModule = Join-Path $PSScriptRoot 'RIDE-Services.psm1'
$script:RideBackgroundAppsModule = Join-Path $PSScriptRoot 'RIDE-BackgroundApps.psm1'
$script:RideBootConfigurationModule = Join-Path $PSScriptRoot 'RIDE-BootConfiguration.psm1'
$script:RideNetworkProfilesModule = Join-Path $PSScriptRoot 'RIDE-NetworkProfiles.psm1'
$script:RideRegistryKeySetModule = Join-Path $PSScriptRoot 'RIDE-RegistryKeySet.psm1'
$script:RidePowerSettingsModule = Join-Path $PSScriptRoot 'RIDE-PowerSettings.psm1'
Import-Module $script:RideSettingsModule -Force -ErrorAction Stop
Import-Module $script:RidePackagesModule -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PackageSelection.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE-PortablePackages.psm1') -ErrorAction Stop
Import-Module $script:RideDefenderModule -Force -ErrorAction Stop
Import-Module $script:RideServicesModule -Force -ErrorAction Stop
Import-Module $script:RideBackgroundAppsModule -Force -ErrorAction Stop
Import-Module $script:RideBootConfigurationModule -Force -ErrorAction Stop
Import-Module $script:RideNetworkProfilesModule -Force -ErrorAction Stop
Import-Module $script:RideRegistryKeySetModule -Force -ErrorAction Stop
Import-Module $script:RidePowerSettingsModule -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE-RegistryValueSet.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE-ManagedSettings.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE-OwnedPowerPlans.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE-LocalPasswordAge.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE-ShellFolders.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE-ProfileSettings.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.StoreApps.psm1') -Force -ErrorAction Stop

function Set-RideLibraryContext {
  <#
  .SYNOPSIS
    Select validated local libraries for subsequent engine commands.
  .DESCRIPTION
    Resolves data into session memory before replacing the active context.
    Omitting Library clears the selection. No Windows state or files are changed.
  .PARAMETER Library
    Explicit local manifest paths; an empty array selects only built-in metadata.
  .EXAMPLE
    Set-RideLibraryContext -Library .\examples\contoso\ride-library.psd1
  .INPUTS
    None.
  .OUTPUTS
    None.
  .NOTES
    Library API 1 reuses RegistryValue and Package handlers. Version follows the module overview.
  #>
  [CmdletBinding()]
  param([string[]] $Library = @())
  $context = Get-RideCatalogContext -Root $script:RideRoot -Library $Library
  $script:RideLibraryContext = if ($Library.Count) { $context } else { $null }
}

function Get-RideCatalog {
  <#
  .SYNOPSIS
    Read the authoritative RIDE catalog data.

  .DESCRIPTION
    Reads built-in data or the validated catalog selected by Set-RideLibraryContext.
    Does not inspect or change Windows state.

  .EXAMPLE
    Get-RideCatalog

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Collections.Hashtable. Catalog SchemaVersion, Operations, and Groups.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  if ($null -ne $script:RideLibraryContext) { return $script:RideLibraryContext.Catalog }
  Import-RideCatalogData -Path $script:RideCatalogPath
}

function Get-RideOperation {
  <#
  .SYNOPSIS
    Find one catalog operation or group by ID.

  .DESCRIPTION
    Returns the first matching operation, then group; unknown IDs throw. No handlers are invoked.

  .PARAMETER Id
    Stable operation or group ID from the catalog; the command checks applicable kinds.

  .EXAMPLE
    Get-RideOperation -Id windows.show-known-extensions

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Collections.Hashtable. Selected operation or group metadata.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][string] $Id)
  $catalog = Get-RideCatalog
  $operation = $catalog.Operations | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
  if ($operation) { return $operation }
  $group = $catalog.Groups | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
  if ($group) { return $group }
  throw "Unknown operation or group ID: $Id"
}

function Get-RideProfile {
  <#
  .SYNOPSIS
    Read and validate a profile data file.

  .DESCRIPTION
    Requires a file, SchemaVersion 1, and selected operations. Does not inspect or apply Windows
    state.

  .PARAMETER Path
    Profile path; defaults to profiles/default.psd1 below the repository root.

  .EXAMPLE
    Get-RideProfile

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Collections.Hashtable. Profile metadata and desired operations.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $Path = (Join-Path $script:RideRoot 'profiles/default.psd1'))
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Profile file not found: $Path" }
  $profile = Import-PowerShellDataFile -LiteralPath $Path
  if ($profile.SchemaVersion -ne 1) { throw "Unsupported profile schema version: $($profile.SchemaVersion)" }
  if (-not $profile.Operations) { throw "Profile '$($profile.Name)' has no operations." }
  $profile
}

function Get-RidePlatform {
  <#
  .SYNOPSIS
    Resolve the engine's Windows target classification from registry data.

  .DESCRIPTION
    Reads build and product type. Returns Windows 11, Windows Server 2025, or an unsupported-target
    message; catalog support remains per operation. Does not mutate system configuration.

  .EXAMPLE
    Get-Help Get-RidePlatform -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.String. Resolved or unsupported Windows target.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  $versionKey = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $productOptions = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -ErrorAction Stop
  $build = [int]$versionKey.CurrentBuildNumber
  if ($productOptions.ProductType -eq 'WinNT' -and $build -ge 22000) { return 'Windows 11' }
  if ($productOptions.ProductType -ne 'WinNT' -and $build -ge 26100) { return 'Windows Server 2025' }
  "Unsupported Windows target: $($versionKey.ProductName) build $build"
}

function Test-RideAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Expand-RideProfileOperations {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Profile,
    [ValidateSet('Apply', 'Remove')][string] $Action = 'Apply'
  )

  $catalog = Get-RideCatalog
  $expanded = New-Object System.Collections.Generic.List[object]
  foreach ($selection in $Profile.Operations) {
    $entry = $catalog.Operations | Where-Object { $_.Id -eq $selection.Id } | Select-Object -First 1
    if ($entry) {
      if($entry.Kind -eq 'StoreApp'){throw 'Use tools/Invoke-RideStoreApps.ps1 for explicit Store app actions; profiles cannot change app registrations.'}
      if ($selection.Variant -and $entry.Kind -ne 'Package') { throw 'Variant requires a package selection.' }
      if ($entry.Kind -eq 'Package') {
        $removing = $Action -eq 'Remove' -or $selection.State -eq 'Absent'
        $entry = Resolve-RideLifecycleSelection -Operation $entry -Variant $selection.Variant -Removal:$removing
      }
      if ($Action -eq 'Remove' -and $entry.Kind -notin @('Package', 'DefenderExclusion')) { continue }
      $state = if ($Action -eq 'Remove') { 'Absent' } elseif ($selection.ContainsKey('State')) { $selection.State } else { $null }
      if ($entry.Kind -in @('RegistryValue', 'RegistryValueSet', 'ShellFolder', 'ProfileSetting') -and $state -eq 'Baseline') { $state = $entry.BaselineState }
      $expanded.Add([pscustomobject]@{ Operation = $entry; State = $state })
      continue
    }

    $group = $catalog.Groups | Where-Object { $_.Id -eq $selection.Id } | Select-Object -First 1
    if (-not $group) { throw "Profile references unknown operation or group: $($selection.Id)" }
    if($group.Workflow -eq 'StoreApps'){throw 'Use tools/Invoke-RideStoreApps.ps1 for explicit Store group actions; profiles cannot change app registrations.'}
    if ($selection.Variant) { throw 'Select variants on individual package entries, not groups.' }
    if ($Action -eq 'Remove' -or $selection.State -eq 'Absent') {
      $members = @($group.Members)
      [array]::Reverse($members)
      $groupState = 'Absent'
    }
    else {
      $members = @($group.Members)
      $groupState = if ($selection.ContainsKey('State')) { $selection.State } else { 'Present' }
    }
    foreach ($memberId in $members) {
      $member = $catalog.Operations | Where-Object { $_.Id -eq $memberId } | Select-Object -First 1
      if ($member.Kind -eq 'Package') { $member = Resolve-RideLifecycleSelection -Operation $member -Removal:($groupState -eq 'Absent') }
      if (-not $member) { throw "Group '$($group.Id)' references unknown operation '$memberId'." }
      $expanded.Add([pscustomobject]@{ Operation = $member; State = if ($member.Kind -in @('Package', 'DefenderExclusion')) { $groupState } else { $null } })
    }
  }

  $expanded.ToArray()
}

function Get-RideOperationValue {
  param([hashtable] $Operation, [string] $State)
  if ($Operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
    if (-not $Operation.States.ContainsKey($State)) { throw 'Unsupported managed setting state.' }
    return $Operation.States[$State]
  }
  if ($Operation.Kind -eq 'RegistryValueSet') {
    if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
    return $Operation.States[$State]
  }
  if ($Operation.Kind -eq 'RegistryValue') {
    if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
    return $Operation.States[$State]
  }
  if ($Operation.Kind -eq 'PowerSetting') {
    if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
    return $Operation.States[$State]
  }
  if ($Operation.Kind -in @('ShellFolder', 'ProfileSetting')) {
    if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
    return $Operation.States[$State]
  }
  if ($Operation.Kind -eq 'Package' -and $State -notin @('Present', 'Absent')) { throw "Package '$($Operation.Id)' requires State Present or Absent." }
  if ($Operation.Kind -eq 'DefenderExclusion' -and $State -notin @('Present', 'Absent')) { throw "Defender exclusion '$($Operation.Id)' requires State Present or Absent." }
  if ($Operation.Kind -eq 'WindowsService') {
    if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
    return $Operation.States[$State]
  }
  if ($Operation.Kind -eq 'NetworkProfile') {
    if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
    return $Operation.States[$State]
  }
  if ($Operation.Kind -eq 'RegistryKeySet') {
    if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'" }
    return $Operation.States[$State]
  }
  if ($Operation.Kind -eq 'BootConfiguration') {
    if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
    return $Operation.States[$State]
  }
  if ($Operation.Kind -eq 'BackgroundAppOverrides' -and $State -ne 'Reset') { throw "Operation '$($Operation.Id)' requires State Reset." }
  $State
}

function Get-RideCurrentState {
  <#
  .SYNOPSIS
    Dispatch read-only live inspection to the catalog handler.

  .DESCRIPTION
    Selects registry, package, Defender, service, background-app, BCD, network, registry-tree,
    power, desktop Shell folder or managed PowerShell profile inspection. Download-only artifacts return a synthetic absence
    record. No apply/remove handlers are invoked.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideCurrentState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Handler-specific captured current state.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)
  switch ($Operation.Handler) {
    'StoreApp' { return Get-RideStoreAppState -Operation $Operation }
    'LocalPasswordMaximumAge' { return Get-RideLocalPasswordAgeState $Operation }
    'OwnedPowerPlan' { return Get-RideOwnedPowerPlanState -Operation $Operation -OwnershipRoot (Join-Path (Get-RideStateRoot -Scope Machine) 'OwnedPowerPlans') }
    { $_ -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge') } { return Get-RideManagedSettingState -Operation $Operation }
    'RegistryValue' { return Get-RideSettingState -Operation $Operation }
    'RegistryValueSet' { return Get-RideRegistryValueSetState -Operation $Operation }
    'Package' { return Get-RideInstalledPackage -Operation $Operation }
    'Artifact' { return [pscustomobject]@{ Present = $false; DisplayName = 'Download-only artifact'; DisplayVersion = $null } }
    'DefenderExclusion' { return Get-RideDefenderExclusionState -Operation $Operation }
    'WindowsService' { return Get-RideWindowsServiceState -Operation $Operation }
    'BackgroundAppOverrides' { return Get-RideBackgroundAppOverrides -Operation $Operation }
    'BootConfiguration' { return Get-RideBootConfigurationState -Operation $Operation }
    'NetworkProfile' { return Get-RideNetworkProfileState -Operation $Operation }
    'RegistryKeySet' { return Get-RideRegistryKeyTreeState -Operation $Operation }
    'PowerSetting' { return Get-RidePowerSettingState -Operation $Operation }
    'ShellFolder' { return Get-RideShellFolderState -Operation $Operation }
    'ProfileSetting' { return Get-RideProfileSettingState -Operation $Operation }
    default { throw "No handler is registered for '$($Operation.Handler)'." }
  }
}

function ConvertTo-RideDisplayValue {
  param($Value)
  if ($null -eq $Value) { return '<unset>' }
  if ($Value -is [hashtable] -and $Value.Count -eq 1 -and $Value.KeepCurrent -eq $true) { return '<keep current>' }
  if ($Value -is [System.Collections.IDictionary]) { return (@($Value.Keys | Sort-Object | ForEach-Object { '{0}: {1}' -f $_, (ConvertTo-RideDisplayValue -Value $Value[$_]) }) -join '; ') }
  if ($Value -is [array]) { return ($Value -join ', ') }
  [string]$Value
}

function Get-RideProfileSettingValueText {
  param([hashtable] $Operation, [string] $State)
  if ($Operation.ProfileSetting -eq 'UserBinPath') {
    if ($State -eq $Operation.UnsetState) { return 'No RIDE user-bin startup PATH block; existing process and persistent PATH preserved' }
    return 'Append existing UserProfile/bin at matching shell startup when absent; process PATH only'
  }
  if ($State -eq $Operation.UnsetState) { return 'No RIDE color override; use configured Terminal appearance' }
  if ($State -eq 'AdminBlue') { return 'Elevated: ' + $Operation.AdminColorScheme + '; normal: configured appearance' }
  'Normal: ' + $Operation.NormalColorScheme + '; elevated: ' + $Operation.AdminColorScheme
}

function Get-RideServiceDesiredValueText {
  param([hashtable] $Desired, [hashtable] $Operation)
  $runtime = if ($Desired.ContainsKey('Status')) { $Desired.Status } else { 'Keep runtime' }
  $text = '{0} / {1}' -f $Desired.StartupType, $runtime
  if (-not $Desired.ContainsKey('DelayedAutoStart') -and -not $Operation.PreserveDelayedAutoStart) { return $text }
  $delay = if ($Desired.ContainsKey('DelayedAutoStart')) { if ($Desired.DelayedAutoStart) { 'On' } else { 'Off' } } else { 'Preserve' }
  return "$text; delay: $delay"
}

function Get-RideFirewallEffectivePolicyText {
  param($CurrentState)
  if (-not $CurrentState.Available) { return 'Unavailable' }
  (@($CurrentState.Entries | ForEach-Object {
    '{0}={1}; source: {2}{3}' -f $_.Name, $_.EffectiveValue, $_.EffectiveSource, $(if ($_.PolicyConflict) { ' (differs from local configuration)' })
  }) -join '; ')
}

function Get-RideCurrentValueText {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $CurrentState
  )

  if ($Operation.Kind -eq 'FirewallProfile') {
    if (-not $CurrentState.Available) { return 'Unavailable' }
    return (@($CurrentState.Entries | ForEach-Object {
      '{0}: local={1}, effective={2}, active={3}{4}' -f $_.Name, $_.Value, $_.EffectiveValue, $_.Active, $(if ($_.PolicyConflict) { ' (policy conflict)' })
    }) -join '; ')
  }
  if ($Operation.Kind -eq 'ProfileSetting') {
    if (-not $CurrentState.Available) { return 'Unavailable: ' + $CurrentState.Reason }
    return '{0}: {1} (startup configuration; session effect not observed)' -f $CurrentState.State, $CurrentState.Path
  }
  if ($Operation.Kind -eq 'RegistryValue') {
    if (-not $CurrentState.Exists) { return '<unset>' }
    return ConvertTo-RideDisplayValue -Value $CurrentState.Value
  }
  if ($Operation.Kind -eq 'RegistryValueSet') {
    $text = (@($CurrentState.Values | ForEach-Object { '{0}: {1} ({2})' -f $_.Key, $(if ($_.Exists) { ConvertTo-RideDisplayValue -Value $_.Value } else { '<unset>' }), $_.ValueType }) -join '; ')
    if ($CurrentState.ReadOnlyObservations) {
      $text += '; Read-only observations: ' + (@($CurrentState.ReadOnlyObservations | ForEach-Object {
        '{0}: {1} ({2})' -f $_.Key, $(if ($_.Exists) { ConvertTo-RideDisplayValue $_.Value } else { '<unset>' }), $_.ValueType
      }) -join '; ')
    }
    return $text
  }
  if ($Operation.Kind -eq 'LocalPasswordMaximumAge') {
    return '{0}; raw {1} seconds; minimum age {2} seconds; {3}' -f $CurrentState.Interpretation, $CurrentState.Policy.MaxAgeSeconds, $CurrentState.Policy.MinAgeSeconds, $CurrentState.EffectivePolicy
  }
  if ($Operation.Kind -eq 'OwnedPowerPlan') {
    return 'Ownership {0}; destination {1}; active {2}; source available {3}; {4}' -f $CurrentState.Stage, $CurrentState.DestinationGuid, $CurrentState.Active, $CurrentState.SourceAvailable, $CurrentState.ConfigurationComparison
  }
  if ($Operation.Kind -eq 'PowerSetting') {
    if (-not $CurrentState.Available) { return 'Unavailable on this device or active power scheme' }
    return '{0} index {1} in scheme {2}' -f $CurrentState.PowerIndex, $CurrentState.Index, $CurrentState.SchemeGuid
  }
  if ($Operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
    if ($CurrentState.PSObject.Properties.Name -contains 'Available' -and -not $CurrentState.Available) { return 'Unavailable' }
    if ($Operation.Kind -eq 'ScheduledTask') { return [string]$CurrentState.Enabled }
    if ($Operation.Kind -eq 'SoundScheme') { return [string]$CurrentState.Selector.Value }
    if ($Operation.Kind -eq 'AdapterBinding') { return (@($CurrentState.Bindings | ForEach-Object { '{0}/{1}: {2}' -f $_.Name, $_.ComponentId, $_.Enabled }) -join '; ') }
    if ($Operation.Kind -in @('NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile')) { return (@($CurrentState.Entries | ForEach-Object { '{0}: {1}' -f $_.Id, $_.Value }) -join '; ') }
    return ConvertTo-RideDisplayValue $CurrentState.Value
  }
  if ($Operation.Kind -eq 'Artifact') { return 'Download only; no configuration is applied' }
  if ($Operation.Kind -eq 'ShellFolder') {
    return '{0}: {1}' -f $(if ($CurrentState.Present) { 'Present' } else { 'Absent' }), $CurrentState.Path
  }
  if ($Operation.Kind -eq 'DefenderExclusion') {
    if (-not $CurrentState.Present) { return '<absent>' }
    return $CurrentState.Path
  }
  if ($Operation.Kind -eq 'WindowsService') {
    $text = '{0} / {1}' -f $CurrentState.StartupType, $CurrentState.Status
    if ($Operation.PreserveDelayedAutoStart) {
      $delay = if ($null -eq $CurrentState.EffectiveDelayedAutoStart) { 'Unknown' } elseif ($CurrentState.EffectiveDelayedAutoStart) { 'On' } else { 'Off' }
      $literal = if ($CurrentState.DelayedAutoStart.Exists) { '{0} ({1})' -f (ConvertTo-RideDisplayValue $CurrentState.DelayedAutoStart.Value), $CurrentState.DelayedAutoStart.ValueType } else { '<unset>' }
      $text += '; SCM delay: {0}{1}; stored delay: {2}' -f $delay, $(if ($CurrentState.StartupType -ne 'Automatic') { ' (inactive for this startup type)' }), $literal
    }
    return $text
  }
  if ($Operation.Kind -eq 'NetworkProfile') {
    if (@($CurrentState.Profiles).Count -eq 0) { return '<no reported non-domain profiles>' }
    return (@($CurrentState.Profiles | ForEach-Object { '{0}: {1}' -f $_.Name, $_.NetworkCategory }) -join '; ')
  }
  if ($Operation.Kind -eq 'RegistryKeySet') {
    $stateName = Get-RideCurrentStateName -Operation $Operation -CurrentState $CurrentState
    return '{0} ({1}/{2} keys registered)' -f $stateName, $CurrentState.PresentCount, $CurrentState.TotalCount
  }
  if ($Operation.Kind -eq 'BootConfiguration') { if ($CurrentState.Exists) { return [string]$CurrentState.Value }; return '<Windows default>' }
  if ($Operation.Kind -eq 'BackgroundAppOverrides') {
    if (-not $CurrentState.Present) { return '<no per-app overrides>' }
    return '{0} per-app override(s)' -f $CurrentState.Count
  }
  if (-not $CurrentState.Present) { return '<absent>' }
  if ($CurrentState.DisplayVersion) {
    return '{0} ({1})' -f $CurrentState.DisplayName, $CurrentState.DisplayVersion
  }
  $CurrentState.DisplayName
}

function Test-RideCurrentStateMatch {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $State,
    [Parameter(Mandatory = $true)] $CurrentState
  )

  if ($Operation.Kind -eq 'ProfileSetting') {
    return ([bool]$CurrentState.Available -and $CurrentState.State -eq $State)
  }
  if ($Operation.Kind -eq 'LocalPasswordMaximumAge') {
    return ($CurrentState.Available -and $CurrentState.GuiCompatible -and $Operation.States.ContainsKey($State) -and $CurrentState.Value -eq $Operation.States[$State])
  }
  if ($Operation.Kind -eq 'OwnedPowerPlan') {
    return ($State -eq 'Create' -and $CurrentState.Available -eq $true -and
      $CurrentState.Value -is [bool] -and $CurrentState.Value -eq $true -and
      $CurrentState.OriginalOwned -eq $true -and $CurrentState.DestinationExists -eq $true -and $CurrentState.Stage -eq 'Ready')
  }
  if ($Operation.Kind -eq 'FirewallProfile') {
    $desired = Get-RideOperationValue $Operation $State
    return ($CurrentState.Available -and @($CurrentState.Entries).Count -eq @($Operation.FirewallProfiles).Count -and
      @($CurrentState.Entries.Name | Sort-Object -Unique).Count -eq @($Operation.FirewallProfiles).Count -and
      @($CurrentState.Entries | Where-Object { $_.Name -notin $Operation.FirewallProfiles -or $_.Value -ne $desired }).Count -eq 0)
  }
  if ($Operation.Kind -eq 'RegistryValue') {
    $desired = Get-RideOperationValue -Operation $Operation -State $State
    if ($null -eq $desired) { return (-not $CurrentState.Exists) }
    if ($Operation.ValueType -eq 'Binary') { return ($CurrentState.Exists -and $CurrentState.ValueType -eq 'Binary' -and (@($CurrentState.Value) -join ',') -ceq (@($desired) -join ',')) }
    return ($CurrentState.Exists -and $CurrentState.ValueType -eq $Operation.ValueType -and $CurrentState.Value -eq $desired)
  }
  if ($Operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
    $desired = Get-RideOperationValue $Operation $State
    if ($Operation.Kind -eq 'SoundScheme') { return Test-RideManagedSoundMatch $Operation $State $CurrentState }
    if ($Operation.Kind -eq 'ScheduledTask') { return ($CurrentState.Available -and $CurrentState.Enabled -eq $desired) }
    if ($Operation.Kind -eq 'AdapterBinding') { return ($CurrentState.Available -and @($CurrentState.Bindings | Where-Object { $_.Enabled -ne $desired }).Count -eq 0) }
    if ($Operation.Kind -eq 'NetBios') { return ($CurrentState.Available -and @($CurrentState.Entries | Where-Object { -not $_.Exists -or $_.ValueType -ne 'DWord' -or $_.Value -ne $desired }).Count -eq 0) }
    if ($Operation.Kind -in @('NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile')) { return ($CurrentState.Available -and @($CurrentState.Entries | Where-Object { $_.Value -ne $desired }).Count -eq 0) }
    return ($CurrentState.Value -eq $desired)
  }
  if ($Operation.Kind -eq 'RegistryValueSet') { return Test-RideRegistryValueSetMatch -Operation $Operation -State $State -CurrentState $CurrentState }
  if ($Operation.Kind -eq 'PowerSetting') { return ([bool]$CurrentState.Available -and [uint32]$CurrentState.Index -eq [uint32](Get-RideOperationValue -Operation $Operation -State $State)) }
  if ($Operation.Kind -eq 'WindowsService') {
    $desired = Get-RideOperationValue -Operation $Operation -State $State
    return ($CurrentState.StartupType -eq $desired.StartupType -and
      (-not $desired.ContainsKey('Status') -or $CurrentState.Status -eq $desired.Status) -and
      (-not $desired.ContainsKey('DelayedAutoStart') -or
       ($CurrentState.EffectiveDelayedAutoStart -is [bool] -and $CurrentState.EffectiveDelayedAutoStart -eq $desired.DelayedAutoStart)))
  }
  if ($Operation.Kind -eq 'NetworkProfile') {
    $desired = [string](Get-RideOperationValue -Operation $Operation -State $State)
    $profiles = @($CurrentState.Profiles)
    return ($profiles.Count -gt 0 -and @($profiles | Where-Object { $_.NetworkCategory -ne $desired }).Count -eq 0)
  }
  if ($Operation.Kind -eq 'RegistryKeySet') {
    $desired = Get-RideOperationValue -Operation $Operation -State $State
    if ($desired -eq 'Absent') { return ($CurrentState.PresentCount -eq 0) }
    return ($CurrentState.PresentCount -eq $CurrentState.TotalCount)
  }
  if ($Operation.Kind -eq 'BootConfiguration') {
    $desired = Get-RideOperationValue -Operation $Operation -State $State
    if ($null -eq $desired) { return (-not $CurrentState.Exists) }
    return ($CurrentState.Exists -and [string]$CurrentState.Value -eq [string]$desired)
  }
  if ($Operation.Kind -eq 'BackgroundAppOverrides') { return (-not [bool]$CurrentState.Present) }
  $desiredPresent = (Get-RideOperationValue -Operation $Operation -State $State) -eq 'Present'
  if ($Operation.InstallerType -eq 'Portable' -and $desiredPresent) { return [bool]$CurrentState.Healthy }
  return ([bool]$CurrentState.Present -eq $desiredPresent)
}

function Get-RideCurrentStateName {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $CurrentState
  )

  if ($Operation.Kind -eq 'OwnedPowerPlan') {
    if ($CurrentState.Value) { return 'Create' }
    if ($CurrentState.OriginalOwned -and -not $CurrentState.DestinationExists) { return 'Owned destination missing' }
    return $CurrentState.Stage
  }
  if ($Operation.Kind -eq 'ProfileSetting') {
    if (-not $CurrentState.Available) { return 'Unavailable' }
    return $CurrentState.State
  }
  if ($Operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
    if ($CurrentState.PSObject.Properties.Name -contains 'Available' -and -not $CurrentState.Available) { return 'Unavailable' }
    foreach ($stateName in $Operation.States.Keys) { if (Test-RideCurrentStateMatch $Operation $stateName $CurrentState) { return $stateName } }
    return 'Custom'
  }
  if ($Operation.Kind -in @('RegistryValueSet') -or ($Operation.Kind -eq 'RegistryValue' -and $Operation.ValueType -eq 'Binary')) {
    foreach ($stateName in $Operation.States.Keys) {
      if (Test-RideCurrentStateMatch -Operation $Operation -State $stateName -CurrentState $CurrentState) { return $stateName }
    }
    return 'Custom'
  }
  if ($Operation.Kind -eq 'WindowsService') {
    # Prefer explicit delay/runtime matches over overlapping compatibility and startup-only presets.
    foreach ($stateName in ($Operation.States.Keys | Sort-Object @{ Expression = {
      $candidate = $Operation.States[$_]
      [int]$candidate.ContainsKey('DelayedAutoStart') * 2 + [int]$candidate.ContainsKey('Status')
    }; Descending = $true }, { $_ })) {
      if (Test-RideCurrentStateMatch $Operation $stateName $CurrentState) { return $stateName }
    }
    return 'Custom'
  }
  if ($Operation.Kind -eq 'PowerSetting') {
    if (-not $CurrentState.Available) { return 'Unavailable' }
    foreach ($stateName in $Operation.States.Keys) {
      if ([uint32]$CurrentState.Index -eq [uint32]$Operation.States[$stateName]) { return $stateName }
    }
    return 'Custom'
  }
  if ($Operation.Kind -eq 'NetworkProfile') {
    $profiles = @($CurrentState.Profiles)
    if ($profiles.Count -eq 0) { return 'Unconfigured' }
    $categories = @($profiles.NetworkCategory | Select-Object -Unique)
    if ($categories.Count -eq 1) { return [string]$categories[0] }
    return 'Mixed'
  }
  if ($Operation.Kind -eq 'RegistryKeySet') {
    if ($CurrentState.PresentCount -eq 0) { return 'Hidden' }
    if ($CurrentState.PresentCount -eq $CurrentState.TotalCount) { return 'Visible' }
    return 'Mixed'
  }
  if ($Operation.Kind -eq 'BootConfiguration') {
    foreach ($stateName in $Operation.States.Keys) {
      $desired = $Operation.States[$stateName]
      if ($null -eq $desired -and -not $CurrentState.Exists) { return $stateName }
      if ($null -ne $desired -and $CurrentState.Exists -and [string]$CurrentState.Value -eq [string]$desired) { return $stateName }
    }
    if ($CurrentState.Exists) { return 'Custom' }
    return 'Unconfigured'
  }
  if ($Operation.Kind -eq 'BackgroundAppOverrides') {
    if (-not $CurrentState.Present) { return 'Reset' }
    return 'Configured'
  }
  if ($Operation.Kind -in @('Package', 'StoreApp', 'DefenderExclusion', 'ShellFolder')) {
    if ($Operation.InstallerType -eq 'Portable' -and $CurrentState.Present -and -not $CurrentState.Healthy) { return 'Incomplete or modified' }
    if ($CurrentState.Present) { return 'Present' }
    return 'Absent'
  }

  foreach ($stateName in $Operation.States.Keys) {
    $value = Get-RideOperationValue -Operation $Operation -State $stateName
    if ($null -eq $value -and -not $CurrentState.Exists) { return $stateName }
    if ($null -ne $value -and $CurrentState.Exists -and
        $CurrentState.ValueType -eq $Operation.ValueType -and $CurrentState.Value -eq $value) {
      return $stateName
    }
  }
  if ($CurrentState.Exists) { return 'Custom' }
  'Unconfigured'
}

function Test-RideDesiredState {
  <#
  .SYNOPSIS
    Inspect whether one operation matches its declared desired state.

  .DESCRIPTION
    Reads current state and compares literal data, presence, service configuration, profile
    categories, or managed tree presence as applicable. Does not apply the requested state.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER State
    Declared desired state for the selected catalog operation.

  .EXAMPLE
    Get-Help Test-RideDesiredState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Boolean. Whether the live operation matches the desired state.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([hashtable] $Operation, [string] $State)
  $current = Get-RideCurrentState -Operation $Operation
  Test-RideCurrentStateMatch -Operation $Operation -State $State -CurrentState $current
}

function Get-RideStateRoot {
  param([ValidateSet('User', 'Machine')][string] $Scope)
  if ($Scope -eq 'Machine') {
    return Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RIDE/State'
  }
  Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RIDE/State'
}

function Get-RideRecordedPackageSelection {
  param([hashtable] $Operation)
  $found = @()
  $scopes = @('Machine', 'User')
  $declaredScopes = @($Operation.Scope)
  foreach ($variant in $Operation.Variants.Values) { if ($variant.Scope) { $declaredScopes += $variant.Scope } }
  # A current-user-only product must not probe the protected machine state store
  # when its caller is unelevated. Elevated recovery still detects older scopes.
  if ('Machine' -notin $declaredScopes -and -not (Test-RideAdministrator)) { $scopes = @('User') }
  foreach ($scope in $scopes) {
    $path = Join-Path (Get-RideStateRoot -Scope $scope) (Join-Path 'PackageSelections' ($Operation.Id + '.json'))
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    if ((Get-Item -LiteralPath $path).Length -gt 1048576) { throw 'Saved package selection exceeds 1 MiB.' }
    $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($record.SchemaVersion -ne 1 -or $record.Operation.Id -ne $Operation.Id -or $record.Operation.Kind -ne 'Package' -or $record.Operation.Scope -ne $scope -or $record.Operation.PackageId -ne $Operation.PackageId -or -not $record.Operation.SelectedVariant) { throw 'Invalid saved package selection index.' }
    if ([string]$record.Operation.Library.Id -ne [string]$Operation.Library.Id) { throw 'Saved selection belongs to another package library.' }
    $saved = @{}; foreach ($property in $record.Operation.PSObject.Properties) { $saved[$property.Name] = $property.Value }
    $found += $saved
  }
  if ($found.Count -gt 1) { throw 'Conflicting saved package scopes require individual review.' }
  if ($found.Count) { return $found[0] }
}

function Resolve-RideLifecycleSelection {
  param([hashtable] $Operation, [string] $Variant, [switch] $Removal)
  if ($Variant -and (($Operation.Variants -and -not $Operation.Variants.ContainsKey($Variant)) -or (-not $Operation.Variants -and $Variant -ne 'installed'))) { throw "Unsupported variant '$Variant' for '$($Operation.Id)'." }
  $recorded = Get-RideRecordedPackageSelection $Operation
  if ($Removal -and $recorded -and (-not $Variant -or $Variant -eq $recorded.SelectedVariant)) { return $recorded }
  $selected = Resolve-RidePackageSelection -Operation $Operation -Variant $Variant
  if ($recorded -and $selected.SelectedVariant -eq $recorded.SelectedVariant -and (Get-RideInstalledPackage -Operation $recorded).Present) { return $recorded }
  return $selected
}

function Save-RidePackageSelectionIndex {
  param([hashtable] $Operation)
  if (-not $Operation.SelectedVariant) { return }
  $root = Initialize-RideStateRoot -Scope $Operation.Scope
  $directory = Join-Path $root 'PackageSelections'
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
  @{ SchemaVersion = 1; Operation = $Operation } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $directory ($Operation.Id + '.json')) -Encoding UTF8
}

function Initialize-RideStateRoot {
  param([ValidateSet('User', 'Machine')][string] $Scope)
  $root = Get-RideStateRoot -Scope $Scope
  New-Item -ItemType Directory -Path $root -Force | Out-Null
  if ($Scope -eq 'Machine') {
    $acl = Get-Acl -LiteralPath $root
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) { $acl.RemoveAccessRuleAll($existingRule) }
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
      $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
      $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
      )
      $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $root -AclObject $acl
  }
  $root
}

function Save-RideOperationSnapshot {
  param([string] $RunId, [hashtable] $Operation, $CurrentState, [string] $DesiredState)
  $key = $null
  if ($Operation.Kind -eq 'RegistryValue' -and $CurrentState.KeyExisted -isnot [bool]) {
    try { $key = Get-Item -LiteralPath $Operation.RegistryPath -ErrorAction Stop }
    catch {
      if ($_.Exception -isnot [Management.Automation.ItemNotFoundException] -and $_.FullyQualifiedErrorId -notlike 'PathNotFound,*') { throw }
    }
  }
  $snapshot = if ($Operation.InstallerType -eq 'Portable') {
    $backup = Join-Path (Initialize-RideStateRoot -Scope $Operation.Scope) (Join-Path $RunId ($Operation.Id + '.files'))
    Save-RidePortableSnapshot -Operation $Operation -BackupDirectory $backup
  }
  elseif ($Operation.Kind -eq 'RegistryValue') {
    [ordered]@{
      Exists = [bool]$CurrentState.Exists
      KeyExisted = $(if ($CurrentState.KeyExisted -is [bool]) { $CurrentState.KeyExisted } else { [bool]($null -ne $key) })
      Value = $CurrentState.Value
      ValueType = $CurrentState.ValueType
    }
  }
  elseif ($Operation.Kind -eq 'RegistryValueSet') {
    [ordered]@{ Values = @($CurrentState.Values) }
  }
  elseif ($Operation.Kind -eq 'LocalPasswordMaximumAge') {
    [ordered]@{ SnapshotVersion = 1; OperationId = $Operation.Id; Prior = $CurrentState.Policy
      ExpectedMaxAgeSeconds = $(if ($Operation.States[$DesiredState] -eq 0) { [long][uint32]::MaxValue } else { [long]$Operation.States[$DesiredState] * 86400 }) }
  }
  elseif ($Operation.Kind -eq 'FirewallProfile') {
    [ordered]@{
      SnapshotVersion = 1; PolicyStore = 'PersistentStore'
      Entries = @($CurrentState.Entries | ForEach-Object {
        [ordered]@{ Name = $_.Name; Value = $_.Value; ExpectedValue = $Operation.States[$DesiredState] }
      })
    }
  }
  elseif ($Operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
    $CurrentState
  }
  elseif ($Operation.Kind -eq 'DefenderExclusion') {
    [ordered]@{ SnapshotVersion = 1; OperationId = $Operation.Id; PathResolver = $Operation.PathResolver
      Present = [bool]$CurrentState.Present; Path = $CurrentState.Path; ExpectedPresent = ($DesiredState -eq 'Present') }
  }
  elseif ($Operation.Kind -eq 'WindowsService') {
    $serviceSnapshot = [ordered]@{ StartupType = $CurrentState.StartupType; Status = $CurrentState.Status }
    if ($Operation.PreserveDelayedAutoStart) {
      $serviceSnapshot.DelayedAutoStart = $CurrentState.DelayedAutoStart
      if ($CurrentState.SnapshotVersion -eq 2) {
        $serviceSnapshot.SnapshotVersion = 2
        $serviceSnapshot.ServiceName = $CurrentState.ServiceName
        $serviceSnapshot.EffectiveDelayedAutoStart = $CurrentState.EffectiveDelayedAutoStart
      }
    }
    $serviceSnapshot
  }
  elseif ($Operation.Kind -eq 'BackgroundAppOverrides') {
    [ordered]@{ Overrides = @($CurrentState.Overrides) }
  }
  elseif ($Operation.Kind -eq 'BootConfiguration') {
    [ordered]@{ Exists = [bool]$CurrentState.Exists; Value = $CurrentState.Value }
  }
  elseif ($Operation.Kind -eq 'NetworkProfile') {
    [ordered]@{ Profiles = @($CurrentState.Profiles | ForEach-Object { [ordered]@{ InterfaceIndex = $_.InterfaceIndex; Name = $_.Name; NetworkCategory = $_.NetworkCategory } }) }
  }
  elseif ($Operation.Kind -eq 'RegistryKeySet') {
    [ordered]@{ Trees = @($CurrentState.Trees) }
  }
  elseif ($Operation.Kind -eq 'PowerSetting') {
    [ordered]@{ SnapshotVersion = 1; SchemeGuid = [string]$CurrentState.SchemeGuid; Index = [uint32]$CurrentState.Index; IndexEncoding = 'UInt32'; PowerIndex = [string]$Operation.PowerIndex }
  }
  elseif ($Operation.Kind -eq 'ProfileSetting') {
    Get-RideProfileSettingSnapshot -Operation $Operation -CurrentState $CurrentState -State $DesiredState
  }
  elseif ($Operation.Kind -eq 'ShellFolder') {
    [ordered]@{
      Path = $CurrentState.Path; Present = [bool]$CurrentState.Present
      HasContents = [bool]$CurrentState.HasContents; Attributes = $CurrentState.Attributes
      CreationTimeUtc = $CurrentState.CreationTimeUtc; LastWriteTimeUtc = $CurrentState.LastWriteTimeUtc
      SecurityDescriptor = $CurrentState.SecurityDescriptor
    }
  }
  else {
    [ordered]@{ Present = [bool]$CurrentState.Present; Version = $CurrentState.DisplayVersion }
  }

  $record = [ordered]@{
    SchemaVersion = 1
    RunId = $RunId
    OperationId = $Operation.Id
    Kind = $Operation.Kind
    Scope = $Operation.Scope
    Snapshot = $snapshot
    CreatedUtc = [DateTime]::UtcNow.ToString('o')
  }
  if ($Operation.Library) { $record.SchemaVersion = 2; $record.Library = $Operation.Library }
  if ($Operation.SelectedVariant) { $record.SchemaVersion = 3; $record.PackageSelection = $Operation }
  $root = Initialize-RideStateRoot -Scope $Operation.Scope
  $fileName = ($Operation.Id -replace '[^a-zA-Z0-9._-]', '_') + '.json'
  $path = Join-Path $root (Join-Path $RunId $fileName)
  New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
  if ($Operation.RecoveryUri) { $record.RecoveryUri = $Operation.RecoveryUri }
  $record | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8
}

function Save-RideRunManifest {
  param([string] $RunId, [object[]] $Plan)
  $scopes = @($Plan | ForEach-Object { $_.Operation.Scope } | Sort-Object -Unique)
  $manifest = [ordered]@{
    SchemaVersion = 1
    RunId = $RunId
    Scopes = $scopes
    OperationIds = @($Plan | ForEach-Object { $_.Operation.Id })
    CreatedUtc = [DateTime]::UtcNow.ToString('o')
  }
  $libraryIdentities = @($Plan | Where-Object { $_.Operation.Library } | ForEach-Object {
    [pscustomobject]@{ Id = $_.Operation.Library.Id; Version = $_.Operation.Library.Version
      EngineApiVersion = $_.Operation.Library.EngineApiVersion; CatalogSha256 = $_.Operation.Library.CatalogSha256 }
  } | Sort-Object Id -Unique)
  if ($libraryIdentities.Count) { $manifest.SchemaVersion = 2; $manifest.Libraries = $libraryIdentities }
  foreach ($scope in $scopes) {
    $root = Initialize-RideStateRoot -Scope $scope
    $directory = Join-Path $root $RunId
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $directory '_manifest.json') -Encoding UTF8
  }
}

function Assert-RidePlanAllowed {
  param([object[]] $Plan)
  $target = Get-RidePlatform
  foreach ($item in $Plan) {
    if ($item.Operation.RequiresDesktopExperience -and $target -like 'Windows Server*') {
      $installationType=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType -ErrorAction Stop).InstallationType
      if ($installationType -ne 'Server') { throw "'$($item.Operation.Id)' requires Windows Server Desktop Experience; applicability is unavailable on '$installationType'." }
    }
    if ($target -notin $item.Operation.SupportedTargets) {
      throw "'$($item.Operation.Id)' does not support $target. Supported: $($item.Operation.SupportedTargets -join ', ')."
    }
    if ($item.Operation.MinimumBuild) {
      $build = [int](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuildNumber -ErrorAction Stop).CurrentBuildNumber
      if ($build -lt $item.Operation.MinimumBuild) { throw "'$($item.Operation.Id)' requires Windows build $($item.Operation.MinimumBuild) or later; detected $build." }
    }
  }
  if (-not $WhatIfPreference -and @($Plan | Where-Object { $_.Operation.RequiresUnelevatedUser }).Count -gt 0 -and (Test-RideAdministrator)) {
    throw 'This current-user package requires a non-elevated PowerShell session to preserve user-only registration.'
  }
  if (-not $WhatIfPreference -and @($Plan | Where-Object { $_.Operation.RequiresAdmin }).Count -gt 0 -and -not (Test-RideAdministrator)) {
    throw 'This plan contains machine operations and must be run from an elevated PowerShell session.'
  }
}

function Get-RidePlan {
  <#
  .SYNOPSIS
    Expand and validate desired operation states without applying them.

  .DESCRIPTION
    Expands ordered group members, reverses removal order, resolves baseline states, and validates
    declared lifecycle actions. Reads saved package selections and their presence when needed;
    does not change Windows or write snapshots.

  .PARAMETER Profile
    Schema-version-1 profile data containing desired catalog IDs and states.

  .PARAMETER Action
    Apply (default) or Remove; removal selects applicable package/exclusion operations.

  .EXAMPLE
    Get-RidePlan -Profile (Get-RideProfile)

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Ordered Operation and State entries.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Profile,
    [ValidateSet('Apply', 'Remove')][string] $Action = 'Apply'
  )
  $plan = @(Expand-RideProfileOperations -Profile $Profile -Action $Action)
  foreach ($item in $plan) {
    if (-not $item.State) { throw "No state was selected for '$($item.Operation.Id)'." }
    $null = Get-RideOperationValue -Operation $item.Operation -State $item.State
    if ($Action -eq 'Apply' -and $item.Operation.Kind -in @('RegistryValue', 'RegistryValueSet', 'DefenderExclusion', 'WindowsService', 'BackgroundAppOverrides', 'BootConfiguration', 'NetworkProfile', 'RegistryKeySet', 'PowerSetting', 'ShellFolder', 'ProfileSetting', 'ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge') -and 'Set' -notin $item.Operation.Actions) { throw "'$($item.Operation.Id)' does not support set." }
    if ($item.Operation.Kind -eq 'Package' -and $item.State -eq 'Present' -and 'Install' -notin $item.Operation.Actions) { throw "'$($item.Operation.Id)' does not support install." }
    if ($item.Operation.Kind -eq 'Package' -and $item.State -eq 'Absent' -and 'Uninstall' -notin $item.Operation.Actions) { throw "'$($item.Operation.Id)' does not support uninstall." }
  }
  $plan
}

function Get-RideSingleOperationPlan {
  <#
  .SYNOPSIS
    Build a validated plan for one direct catalog action.

  .DESCRIPTION
    Requires an appropriate operation ID rather than a group. Resolves Set, Unset, Install, or
    Remove into a synthetic profile and returns the normal plan without applying it.

  .PARAMETER Id
    Stable operation or group ID from the catalog; the command checks applicable kinds.

  .PARAMETER Action
    Set, Unset, Install, or Remove; determines applicable operation kinds and desired states.

  .PARAMETER State
    Declared setting state for Set; required for that action, otherwise derived from the action.

  .PARAMETER Variant
    Explicit catalog package variant; unsupported choices fail without fallback.

  .EXAMPLE
    Get-RideSingleOperationPlan -Id package.7zip -Action Install

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Ordered Operation and State entries.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][string] $Id,
    [ValidateSet('Set', 'Unset', 'Install', 'Remove')][string] $Action,
    [string] $State,
    [string] $Variant
  )

  $operation = Get-RideOperation -Id $Id
  if (-not $operation.ContainsKey('Kind')) { throw "Direct actions require an operation ID, not a group ID: $Id" }
  switch ($Action) {
    'Set' {
      if ($operation.Kind -notin @('RegistryValue', 'RegistryValueSet', 'DefenderExclusion', 'WindowsService', 'BackgroundAppOverrides', 'BootConfiguration', 'NetworkProfile', 'RegistryKeySet', 'PowerSetting', 'ShellFolder', 'ProfileSetting', 'ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) { throw "'set' requires a Windows setting ID; '$Id' is a $($operation.Kind) operation." }
      if (-not $State) {
        $availableStates = if ($operation.Kind -in @('RegistryValue', 'RegistryValueSet', 'WindowsService', 'BackgroundAppOverrides', 'BootConfiguration', 'NetworkProfile', 'RegistryKeySet', 'PowerSetting', 'ShellFolder', 'ProfileSetting', 'ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) { $operation.States.Keys -join ', ' } else { 'Present, Absent' }
        throw "The set command requires -State. Available states: $availableStates."
      }
      if ('Set' -notin $operation.Actions) { throw "'$Id' does not support setting a value." }
    }
    'Unset' {
      if ($operation.Kind -eq 'ProfileSetting') { $State = $operation.UnsetState }
      elseif ($operation.Kind -in @('DefenderExclusion', 'ShellFolder')) {
        $State = 'Absent'
      }
      elseif ($operation.Kind -eq 'RegistryValueSet') { $State = 'WindowsDefault' }
      elseif ($operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) { throw "'$Id' has no declared override-removal state. Set an explicit state or restore a captured run." }
      elseif ($operation.Kind -ne 'RegistryValue') { throw "'unset' requires a Windows setting ID; '$Id' is a $($operation.Kind) operation." }
      if ($operation.Kind -eq 'RegistryValue') {
        $unsetStates = @($operation.States.Keys | Where-Object { $null -eq $operation.States[$_] })
        if ($unsetStates.Count -eq 0) { throw "'$Id' has no declared unset state." }
        $State = $unsetStates[0]
      }
      if ('Set' -notin $operation.Actions) { throw "'$Id' does not support setting a value." }
    }
    'Install' {
      if ($operation.Kind -ne 'Package') { throw "'install' requires a package ID; '$Id' is a $($operation.Kind) operation." }
      $State = 'Present'
      if ('Install' -notin $operation.Actions) { throw "'$Id' does not support installation." }
    }
    'Remove' {
      if ($operation.Kind -ne 'Package') { throw "'remove -Id' requires a package ID; '$Id' is a $($operation.Kind) operation." }
      $State = 'Absent'
      if ('Uninstall' -notin $operation.Actions) { throw "'$Id' does not support uninstallation." }
    }
  }
  $profile = @{
    SchemaVersion = 1
    Name = "Direct $Action for $Id"
    Operations = @(@{ Id = $Id; State = $State })
  }
  if ($Variant) { $profile.Operations[0].Variant = $Variant }
  Get-RidePlan -Profile $profile
}

function Save-RidePackage {
  <#
  .SYNOPSIS
    Download a catalog package or standalone artifact without installing it.

  .DESCRIPTION
    Requires a declared Download action and Package/Artifact kind. Uses ShouldProcess before
    network/file writes. Downloads do not create pre-change Windows setting snapshots.

  .PARAMETER Id
    Stable operation or group ID from the catalog; the command checks applicable kinds.

  .PARAMETER Variant
    Explicit catalog package variant for download.

  .PARAMETER Destination
    Artifact destination root; defaults to the user RIDE state root Artifacts directory.

  .PARAMETER GitHubAuthentication
    Anonymous (default) or explicit PAT for GitHub release discovery only.

  .PARAMETER GitHubCredentialReference
    Nonsecret enrolled reference required with PAT. Resolved only during acquisition.

  .EXAMPLE
    Save-RidePackage -Id package.7zip -WhatIf

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Artifact retention record when approved.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
  param(
    [Parameter(Mandatory = $true)][string] $Id,
    [string] $Variant,
    [string] $Destination = (Join-Path (Get-RideStateRoot -Scope User) 'Artifacts'),
    [ValidateSet('Anonymous','PAT')][string] $GitHubAuthentication = 'Anonymous',
    [string] $GitHubCredentialReference
  )

  $operation = Get-RideOperation -Id $Id
  $operation = Resolve-RidePackageSelection -Operation $operation -Variant $Variant
  if ($operation.Kind -notin @('Package', 'Artifact')) { throw "The download command requires a package or artifact ID; '$Id' is a $($operation.Kind) operation." }
  if ('Download' -notin $operation.Actions) { throw "Catalog item '$Id' does not support download." }
  if ($PSCmdlet.ShouldProcess($operation.Name, "Download latest artifact to '$Destination'")) {
    Save-RidePackageArtifact -Operation $operation -DestinationDirectory $Destination -GitHubAuthentication $GitHubAuthentication -GitHubCredentialReference $GitHubCredentialReference
  }
}

function Invoke-RidePlan {
  <#
  .SYNOPSIS
    Apply ordered desired states with preview and pre-change capture.

  .DESCRIPTION
    Checks target/elevation, skips matching states, and uses ShouldProcess before
    snapshots/handlers. Writes manifests and per-scope snapshots only for approved changes. Failure
    reports run ID plus saved/completed operations; prior approved changes can remain.

  .PARAMETER Plan
    Ordered operation/state objects returned by Get-RidePlan or Get-RideSingleOperationPlan.

  .PARAMETER GitHubAuthentication
    Anonymous (default) or explicit PAT for GitHub release discovery only.

  .PARAMETER GitHubCredentialReference
    Nonsecret enrolled reference required with PAT. Resolved only during acquisition.

  .EXAMPLE
    Invoke-RidePlan -Plan (Get-RidePlan -Profile (Get-RideProfile)) -WhatIf

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.String. Applied/already-matching/no-change messages and saved Run ID.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
  param(
    [Parameter(Mandatory = $true)][object[]] $Plan,
    [ValidateSet('Anonymous','PAT')][string] $GitHubAuthentication = 'Anonymous',
    [string] $GitHubCredentialReference
  )
  Assert-RidePlanAllowed -Plan $Plan
  $runId = [guid]::NewGuid().ToString('N')
  $savedOperationIds = New-Object System.Collections.Generic.List[string]
  $completedOperationIds = New-Object System.Collections.Generic.List[string]
  $manifestSaved = $false
  foreach ($item in $Plan) {
    $operation = $item.Operation
    if ($operation.Kind -eq 'Package') {
      $product = Get-RideOperation -Id $operation.Id
      $recorded = Get-RideRecordedPackageSelection $product
      if ($recorded -and $recorded.SelectedVariant -ne $operation.SelectedVariant -and (Get-RideInstalledPackage -Operation $recorded).Present) { throw "Existing different edition '$($recorded.SelectedVariant)' for '$($operation.Id)'; use an explicit reviewed migration." }
      if ($product.Variants) {
        foreach ($variantName in $product.Variants.Keys | Where-Object { $_ -ne $operation.SelectedVariant }) {
          $other = if ($recorded -and $recorded.SelectedVariant -eq $variantName) { $recorded } else { Resolve-RidePackageSelection -Operation $product -Variant $variantName }
          if ((Get-RideInstalledPackage -Operation $other).Present) { throw "Existing different edition '$variantName' for '$($operation.Id)'; use an explicit reviewed migration." }
        }
      }
    }
    $before = Get-RideCurrentState -Operation $operation
    if ($before.PSObject.Properties.Name -contains 'Available' -and -not $before.Available) { throw "Operation '$($operation.Id)' is unavailable on this device; no state was saved or changed." }
    if (Test-RideDesiredState -Operation $operation -State $item.State) {
      Write-Output ("Already in desired state: {0} ({1})" -f $operation.Id, $item.State)
      continue
    }
    if ($PSCmdlet.ShouldProcess($operation.Name, "Set state to $($item.State)")) {
      try {
        if (-not $manifestSaved) {
          Save-RideRunManifest -RunId $runId -Plan $Plan
          $manifestSaved = $true
        }
        Save-RideOperationSnapshot -RunId $runId -Operation $operation -CurrentState $before -DesiredState $item.State
        $savedOperationIds.Add($operation.Id)
        if ($operation.Kind -eq 'RegistryValue') {
          $value = Get-RideOperationValue -Operation $operation -State $item.State
          Set-RideSettingState -Operation $operation -Value $value
        }
        elseif ($operation.Kind -eq 'RegistryValueSet') {
          Set-RideRegistryValueSetState -Operation $operation -State $item.State
        }
        elseif ($operation.Kind -eq 'LocalPasswordMaximumAge') { Set-RideLocalPasswordAgeState -Operation $operation -State $item.State -ExpectedState $before }
        elseif ($operation.Kind -eq 'OwnedPowerPlan') { Set-RideOwnedPowerPlanState -Operation $operation -State $item.State -ExpectedState $before -OwnershipRoot (Join-Path (Get-RideStateRoot -Scope Machine) 'OwnedPowerPlans') }
        elseif ($operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) { Set-RideManagedSettingState -Operation $operation -State $item.State -ExpectedState $before }
        elseif ($operation.Kind -eq 'Package') {
          Save-RidePackageSelectionIndex -Operation $operation
          if ($item.State -eq 'Present') {
            $cache = Join-Path (Get-RideStateRoot -Scope $operation.Scope) 'Cache'
            $artifact = Install-RidePackage -Operation $operation -CacheDirectory $cache -GitHubAuthentication $GitHubAuthentication -GitHubCredentialReference $GitHubCredentialReference
            if ($artifact) {
              $recordPath = Join-Path (Get-RideStateRoot -Scope $operation.Scope) (Join-Path $runId (($operation.Id -replace '[^a-zA-Z0-9._-]', '_') + '.json'))
              $savedRecord = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
              $savedRecord | Add-Member -NotePropertyName AppliedArtifact -NotePropertyValue $artifact -Force
              $savedRecord | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $recordPath -Encoding UTF8
            }
          }
          else {
            Uninstall-RidePackage -Operation $operation
          }
        }
        elseif ($operation.Kind -eq 'DefenderExclusion') {
          Set-RideDefenderExclusionState -Operation $operation -State $item.State -ExpectedState $before
        }
        elseif ($operation.Kind -eq 'WindowsService') {
          Set-RideWindowsServiceState -Operation $operation -State $item.State
        }
        elseif ($operation.Kind -eq 'BackgroundAppOverrides') {
          Reset-RideBackgroundAppOverrides -Operation $operation
        }
        elseif ($operation.Kind -eq 'BootConfiguration') {
          Set-RideBootConfigurationState -Operation $operation -State $item.State
        }
        elseif ($operation.Kind -eq 'NetworkProfile') {
          Set-RideNetworkProfileState -Operation $operation -State $item.State
        }
        elseif ($operation.Kind -eq 'RegistryKeySet') {
          Set-RideRegistryKeySetState -Operation $operation -State $item.State
        }
        elseif ($operation.Kind -eq 'PowerSetting') {
          Set-RidePowerSettingState -Operation $operation -State $item.State
        }
        elseif ($operation.Kind -eq 'ShellFolder') {
          Set-RideShellFolderState -Operation $operation -State $item.State
        }
        elseif ($operation.Kind -eq 'ProfileSetting') {
          Set-RideProfileSettingState -Operation $operation -State $item.State -ExpectedState $before -Confirm:$false
        }
        $completedOperationIds.Add($operation.Id)
        Write-Output ("Applied: {0} ({1})" -f $operation.Id, $item.State)
      }
      catch {
        $savedList = if ($savedOperationIds.Count) { $savedOperationIds -join ', ' } else { '<none>' }
        $completedList = if ($completedOperationIds.Count) { $completedOperationIds -join ', ' } else { '<none>' }
        throw "RIDE operation '$($operation.Id)' failed. Run ID: $runId. Saved state: $savedList. Completed operations: $completedList. Error: $($_.Exception.Message)"
      }
    }
  }
  if (-not $WhatIfPreference) {
    if ($savedOperationIds.Count -gt 0) {
      Write-Output "Run ID: $runId"
      return
    }
    Write-Output 'No changes were needed; no state record was created.'
  }
}

function Show-RideCatalog {
  <#
  .SYNOPSIS
    Return pipeline-friendly catalog and profile discovery objects.

  .DESCRIPTION
    Builds one object collection of operations, groups, and profiles. Filters by a named view or
    catalog category; unknown/empty views throw. No handlers are invoked.

  .PARAMETER View
    all (default), profiles, packages, artifacts, groups, settings, or a catalog category.

  .EXAMPLE
    Show-RideCatalog -View packages

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Type, Id, Name, Category, Kind, scope/actions,
    members/path, description, supported targets, and publisher/license reference fields.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $View = 'all')

  $catalog = Get-RideCatalog
  $rows = New-Object System.Collections.Generic.List[object]
  foreach ($row in Get-RideCatalogRows -Catalog $catalog) { $rows.Add($row) }
  $profileFiles = if ($null -ne $script:RideLibraryContext) { $script:RideLibraryContext.ProfileFiles } else { @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../profiles') -Filter '*.psd1' -File) }
  foreach ($profileFile in $profileFiles) {
    $profile = Import-PowerShellDataFile -LiteralPath $profileFile.FullName
    $rows.Add([pscustomobject]@{
      Type = 'Profile'
      Id = [IO.Path]::GetFileNameWithoutExtension($profileFile.Name)
      Name = $profile.Name
      Category = 'Profiles'
      Kind = 'Profile'
      Scope = ''
      RequiresAdmin = $null
      AppliesTo = 'Defined by selected members; inspect the profile plan'
      Behavior = 'Varies by member'
      GuiEffect = 'Defined by each member'
      GuiPath = $null
      Requirements = 'All selected member requirements apply; inspect the profile plan'
      OtherSupportedChoices = 'Defined by each member; selection does not change a published scope'
      EffectivePolicy = $null
      ExecutionIdentity = $null
      Actions = @()
      Members = @($profile.Operations | ForEach-Object { $_.Id })
      Path = if ($null -ne $script:RideLibraryContext -and $profileFile.DirectoryName -ne (Join-Path $script:RideRoot 'profiles')) { $profileFile.FullName } else { Join-Path 'profiles' $profileFile.Name }
      Description = $profile.Description
      SupportedTargets = @()
      ProductUri = $null
      License = $null
      LicenseUri = $null
      TermsUri = $null
    })
  }

  $filtered = @(Select-RideCatalogView -Catalog $catalog -Rows $rows.ToArray() -View $View -IncludeProfiles)
  if (-not $filtered -or @($filtered).Count -eq 0) { throw "Unknown or empty list view '$View'. Use all, profiles, packages, artifacts, groups, settings, or a catalog category such as windows, explorer, or security." }
  $filtered | Sort-Object Type, Category, Name, Id
}

function Show-RideOperation {
  <#
  .SYNOPSIS
    Display operation metadata with its live value or group member state.

  .DESCRIPTION
    Reads focused current-state handlers, includes a registry baseline value, and formats operation
    details or group members for human inspection. Does not change Windows state.

  .PARAMETER Id
    Stable operation or group ID from the catalog; the command checks applicable kinds.

  .PARAMETER Variant
    Optional explicit package edition for live inspection.

  .EXAMPLE
    Get-Help Show-RideOperation -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    Microsoft.PowerShell.Commands.Internal.Format formatting records for list/table display.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][string] $Id, [string] $Variant)
  $entry = Get-RideOperation -Id $Id
  if ($entry.Kind -eq 'Package') { $entry = Resolve-RideLifecycleSelection -Operation $entry -Variant $Variant -Removal:(-not $Variant) } elseif ($Variant) { throw 'Variant requires a package ID.' }
  if (-not $entry.ContainsKey('Kind')) {
    [pscustomobject]$entry | Format-List
    $catalog = Get-RideCatalog
    $members = foreach ($memberId in $entry.Members) {
      $operation = $catalog.Operations | Where-Object { $_.Id -eq $memberId } | Select-Object -First 1
      if (-not $operation) { continue }
      $current = Get-RideCurrentState -Operation $operation
      [pscustomobject]@{
        Id = $operation.Id
        Name = $operation.Name
        CurrentValue = Get-RideCurrentValueText -Operation $operation -CurrentState $current
        CurrentValueType = if ($operation.Kind -eq 'RegistryValue') { $current.ValueType } elseif ($operation.Kind -eq 'RegistryValueSet') { 'Coordinated registry values' } elseif ($operation.Kind -eq 'PowerSetting') { 'Power setting index' } elseif ($operation.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } elseif ($operation.Kind -eq 'WindowsService') { 'Service configuration' } elseif ($operation.Kind -eq 'BackgroundAppOverrides') { 'Per-app registry values' } elseif ($operation.Kind -eq 'BootConfiguration') { 'Boot configuration' } elseif ($operation.Kind -eq 'NetworkProfile') { 'Connection profiles' } elseif ($operation.Kind -eq 'RegistryKeySet') { 'Registry key set' } elseif ($operation.Kind -eq 'ShellFolder') { 'Desktop Shell folder' } elseif ($operation.Kind -eq 'ProfileSetting') { 'PowerShell startup profile setting' } elseif ($operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) { $operation.Kind } else { 'Package' }
      }
    }
    $memberRows = foreach ($member in $members) {
      $operation = $catalog.Operations | Where-Object Id -eq $member.Id | Select-Object -First 1
      $member | Add-RideSettingPresentation -Operation $operation -IncludeExecutionIdentity
    }
    $memberRows | Format-List
    return
  }

  $current = Get-RideCurrentState -Operation $entry
  $details = [ordered]@{}
  foreach ($key in $entry.Keys) {
    if ($key -ne 'States') { $details[$key] = $entry[$key] }
  }
  $presentation = Get-RideSettingPresentation -Operation $entry -IncludeExecutionIdentity
  if ($entry.Kind -eq 'FirewallProfile') { $presentation.EffectivePolicy = Get-RideFirewallEffectivePolicyText $current }
  foreach ($property in $presentation.PSObject.Properties) { $details[$property.Name] = $property.Value }
  $details.CurrentValue = Get-RideCurrentValueText -Operation $entry -CurrentState $current
  $details.CurrentValueType = if ($entry.Kind -eq 'RegistryValue') { $current.ValueType } elseif ($entry.Kind -eq 'RegistryValueSet') { 'Coordinated registry values' } elseif ($entry.Kind -eq 'PowerSetting') { 'Power setting index' } elseif ($entry.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } elseif ($entry.Kind -eq 'WindowsService') { 'Service configuration' } elseif ($entry.Kind -eq 'BackgroundAppOverrides') { 'Per-app registry values' } elseif ($entry.Kind -eq 'BootConfiguration') { 'Boot configuration' } elseif ($entry.Kind -eq 'NetworkProfile') { 'Connection profiles' } elseif ($entry.Kind -eq 'RegistryKeySet') { 'Registry key set' } elseif ($entry.Kind -eq 'ShellFolder') { 'Desktop Shell folder' } elseif ($entry.Kind -eq 'ProfileSetting') { 'PowerShell startup profile setting' } elseif ($entry.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) { $entry.Kind } elseif ($entry.Kind -eq 'Artifact') { 'Download-only artifact' } else { 'Package' }
  if ($entry.Kind -eq 'RegistryValue') {
    $baselineValue = Get-RideOperationValue -Operation $entry -State $entry.BaselineState
    $details.BaselineValue = ConvertTo-RideDisplayValue -Value $baselineValue
  }
  elseif ($entry.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
    $details.BaselineValue = '<not declared; restore a captured run>'
    if ($entry.Kind -eq 'FirewallProfile') {
      $details.Profiles = $current.Entries
      $details.ActiveNetworks = $current.ActiveNetworks
      $details.LegacyStandardProfileKeyPresent = $current.LegacyStandardProfileKeyPresent
      $details.CanRestoreLocal = $current.CanRestoreLocal
    }
    if ($entry.Kind -eq 'OwnedPowerPlan') {
      $details.DestinationGuid = $current.DestinationGuid
      $details.SourceAvailable = $current.SourceAvailable
      $details.Active = $current.Active
      $details.OwnershipStage = $current.Stage
      $details.ConfigurationComparison = $current.ConfigurationComparison
    }
    if ($entry.Kind -eq 'LocalPasswordMaximumAge') {
      $details.AppliedLocalPolicy = $current.Policy
      $details.PolicySource = $current.EffectivePolicy
      $details.GuiCompatible = $current.GuiCompatible
    }
  }
  elseif ($entry.Kind -eq 'DefenderExclusion') {
    $details.Present = [bool]$current.Present
  }
  elseif ($entry.Kind -eq 'RegistryValueSet') {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
    $details.Values = @($current.Values)
    if ($current.ReadOnlyObservations) { $details.ReadOnlyObservations = @($current.ReadOnlyObservations) }
    $details.BaselineValue = ConvertTo-RideDisplayValue -Value $entry.States[$entry.BaselineState]
  }
  elseif ($entry.Kind -eq 'WindowsService') {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
    if ($current.Dependencies) { $details.DependencyState = $current.Dependencies }
    if ($entry.BaselineState) { $details.BaselineValue = Get-RideServiceDesiredValueText -Desired $entry.States[$entry.BaselineState] -Operation $entry }
    if ($entry.PreserveDelayedAutoStart) {
      $details.EffectiveDelayedAutoStart = $current.EffectiveDelayedAutoStart
      $details.DelayedAutoStart = $current.DelayedAutoStart
    }
  }
  elseif ($entry.Kind -eq 'BackgroundAppOverrides') {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
  }
  elseif ($entry.Kind -eq 'BootConfiguration') {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
  }
  elseif ($entry.Kind -eq 'NetworkProfile') {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
    $details.Profiles = @($current.Profiles)
  }
  elseif ($entry.Kind -eq 'RegistryKeySet') {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
    $details.RegisteredKeyCount = $current.PresentCount
    $details.RegistryKeyCount = $current.TotalCount
  }
  elseif ($entry.Kind -eq 'PowerSetting') {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
  }
  elseif ($entry.Kind -eq 'ShellFolder') {
    $details.CurrentValueType = 'Desktop Shell folder'
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
    $details.Path = $current.Path
    $details.HasContents = $current.HasContents
    $details.BaselineValue = $entry.States[$entry.BaselineState]
  }
  elseif ($entry.Kind -eq 'ProfileSetting') {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
    $details.Path = $current.Path
    $details.Available = $current.Available
    $details.BaselineValue = $entry.BaselineState
    $details.AppearanceObservation = 'Managed startup configuration only; open a new interactive Windows Terminal shell to observe colors.'
  }
  else {
    $details.Installed = [bool]$current.Present
  }
  [pscustomobject]$details | Format-List
}

function Show-RidePlan {
  <#
  .SYNOPSIS
    Display current values next to an ordered plan's desired values.

  .DESCRIPTION
    Inspects live values and desired-state matches, then formats a table with scope/rollback
    information. Does not apply the plan or create state records.

  .PARAMETER Plan
    Ordered operation/state objects returned by Get-RidePlan or Get-RideSingleOperationPlan.

  .EXAMPLE
    Get-Help Show-RidePlan -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    Microsoft.PowerShell.Commands.Internal.Format formatting records for table display.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][object[]] $Plan)
  $rows = foreach ($item in $Plan) {
    $current = Get-RideCurrentState -Operation $item.Operation
    $desiredValue = if ($item.Operation.Kind -in @('RegistryValue', 'RegistryValueSet', 'ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
      ConvertTo-RideDisplayValue -Value (Get-RideOperationValue -Operation $item.Operation -State $item.State)
    }
    elseif ($item.Operation.Kind -eq 'ProfileSetting') {
      Get-RideProfileSettingValueText $item.Operation $item.State
    }
    elseif ($item.Operation.Kind -eq 'WindowsService') {
      $desired = Get-RideOperationValue -Operation $item.Operation -State $item.State
      Get-RideServiceDesiredValueText -Desired $desired -Operation $item.Operation
    }
    elseif ($item.Operation.Kind -eq 'PowerSetting') {
      '{0} (index {1})' -f $item.State, (Get-RideOperationValue -Operation $item.Operation -State $item.State)
    }
    else {
      $item.State
    }
    $row = [pscustomobject]@{
      Id = $item.Operation.Id
      Name = $item.Operation.Name
      Action = if ($item.Operation.Kind -eq 'Package' -and $item.State -eq 'Absent') { 'Uninstall' } elseif ($item.Operation.Kind -eq 'Package') { 'Install' } else { 'Set' }
      CurrentValue = Get-RideCurrentValueText -Operation $item.Operation -CurrentState $current
      DesiredState = $item.State
      DesiredValue = $desiredValue
      InDesiredState = Test-RideCurrentStateMatch -Operation $item.Operation -State $item.State -CurrentState $current
      Scope = $item.Operation.Scope
      Rollback = $item.Operation.Rollback
      Variant = $item.Operation.SelectedVariant
      Provider = $item.Operation.DownloadProvider
      Destination = $item.Operation.InstallDirectory
      SelectionNote = $item.Operation.SelectionNote
    } | Add-RideSettingPresentation -Operation $item.Operation -IncludeExecutionIdentity
    if ($item.Operation.Kind -eq 'FirewallProfile') { $row.EffectivePolicy = Get-RideFirewallEffectivePolicyText $current }
    $row
  }
  if (@($Plan | Where-Object { $_.Operation.Kind -notin @('Package', 'Artifact') }).Count) {
    $rows | Format-List
  }
  else { $rows | Format-Table -AutoSize }
}

function Test-RideStatusView {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $View,
    [Parameter(Mandatory = $true)][hashtable] $Catalog
  )

  $viewKey = $View.ToLowerInvariant()
  switch -Regex ($viewKey) {
    '^all$' { return $true }
    '^profiles?$' { throw "The 'profiles' view applies to list. For status, select one profile with -Profile <file>." }
    '^packages?$' { return ($Operation.Kind -eq 'Package') }
    '^settings?$' { return ($Operation.Kind -in @('RegistryValue', 'RegistryValueSet', 'DefenderExclusion', 'WindowsService', 'BackgroundAppOverrides', 'BootConfiguration', 'NetworkProfile', 'RegistryKeySet', 'PowerSetting', 'ShellFolder', 'ProfileSetting', 'ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) }
    '^groups?$' {
      return [bool]($Catalog.Groups | Where-Object { $Operation.Id -in $_.Members } | Select-Object -First 1)
    }
    default {
      $row = [pscustomobject]@{ Type = 'Operation'; Kind = $Operation.Kind; Category = $Operation.Category }
      return (@(Select-RideCatalogView -Catalog $Catalog -Rows @($row) -View $View).Count -gt 0)
    }
  }
}

function Get-RideStatus {
  <#
  .SYNOPSIS
    Compare live state with target defaults or an explicit profile.

  .DESCRIPTION
    Without Profile, returns each target-supported operation's literal/effective defaults and
    interpreted current state. With Profile, compares selected desired states. Applies a catalog
    view; standalone artifacts are excluded from target-default status.
    Image-dependent registry defaults report <platform-defined> with MatchesDefault=null;
    absence is not assumed to match a default that has not been established.

  .PARAMETER Profile
    Optional schema-version-1 profile. Omit to inspect platform defaults; supplying it switches to
    desired-state comparison.

  .PARAMETER View
    all (default), packages, groups, settings, or a catalog category. profiles is rejected; supply
    Profile for comparisons.

  .EXAMPLE
    Get-Help Get-RideStatus -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Current values/states with default or desired-state
    fields.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([hashtable] $Profile, [string] $View = 'all')

  if ($View -match '^(?i:profiles?)$') { throw "The 'profiles' view applies to list. For status, select one profile with -Profile <file>." }
  $catalog = Get-RideCatalog
  $rows = New-Object System.Collections.Generic.List[object]

  if ($PSBoundParameters.ContainsKey('Profile')) {
    $plan = @(Get-RidePlan -Profile $Profile)
    foreach ($item in $plan) {
      if (-not (Test-RideStatusView -Operation $item.Operation -View $View -Catalog $catalog)) { continue }
      $current = Get-RideCurrentState -Operation $item.Operation
      $desiredValue = if ($item.Operation.Kind -in @('RegistryValue', 'RegistryValueSet', 'ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
        ConvertTo-RideDisplayValue -Value (Get-RideOperationValue -Operation $item.Operation -State $item.State)
      }
      elseif ($item.Operation.Kind -eq 'ProfileSetting') {
        Get-RideProfileSettingValueText $item.Operation $item.State
      }
      elseif ($item.Operation.Kind -eq 'WindowsService') {
        $desired = Get-RideOperationValue -Operation $item.Operation -State $item.State
        Get-RideServiceDesiredValueText -Desired $desired -Operation $item.Operation
      }
      else {
        $item.State
      }
      $presentation = Get-RideSettingPresentation -Operation $item.Operation -IncludeExecutionIdentity
      if ($item.Operation.Kind -eq 'FirewallProfile') { $presentation.EffectivePolicy = Get-RideFirewallEffectivePolicyText $current }
      $rows.Add([pscustomobject]@{
        Id = $item.Operation.Id
        Name = $item.Operation.Name
        Scope = $item.Operation.Scope
        RequiresAdmin = $item.Operation.RequiresAdmin
        AppliesTo = $presentation.AppliesTo
        Behavior = $presentation.Behavior
        GuiEffect = $presentation.GuiEffect
        GuiPath = $presentation.GuiPath
        Requirements = $presentation.Requirements
        OtherSupportedChoices = $presentation.OtherSupportedChoices
        EffectivePolicy = $presentation.EffectivePolicy
        ExecutionIdentity = $presentation.ExecutionIdentity
        DesiredState = $item.State
        DesiredValue = $desiredValue
        InDesiredState = Test-RideCurrentStateMatch -Operation $item.Operation -State $item.State -CurrentState $current
        CurrentState = Get-RideCurrentStateName -Operation $item.Operation -CurrentState $current
        CurrentValue = Get-RideCurrentValueText -Operation $item.Operation -CurrentState $current
        CurrentValueType = if ($item.Operation.Kind -eq 'RegistryValue') { if ($current.Exists) { $current.ValueType } else { '<unset>' } } elseif ($item.Operation.Kind -eq 'RegistryValueSet') { 'Coordinated registry values' } elseif ($item.Operation.Kind -eq 'PowerSetting') { 'Power setting index' } elseif ($item.Operation.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } elseif ($item.Operation.Kind -eq 'WindowsService') { 'Service configuration' } elseif ($item.Operation.Kind -eq 'BackgroundAppOverrides') { 'Per-app registry values' } elseif ($item.Operation.Kind -eq 'BootConfiguration') { 'Boot configuration' } elseif ($item.Operation.Kind -eq 'NetworkProfile') { 'Connection profiles' } elseif ($item.Operation.Kind -eq 'RegistryKeySet') { 'Registry key set' } elseif ($item.Operation.Kind -eq 'ShellFolder') { 'Desktop Shell folder' } elseif ($item.Operation.Kind -eq 'ProfileSetting') { 'PowerShell startup profile setting' } elseif ($item.Operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) { $item.Operation.Kind } else { 'Package' }
      })
    }
  }
  else {
    $target = Get-RidePlatform
  foreach ($operation in $catalog.Operations) {
      if ($operation.Kind -eq 'Artifact') { continue }
      if (-not (Test-RideStatusView -Operation $operation -View $View -Catalog $catalog)) { continue }
      if ($operation.PendingAcceptance) { continue }
      if ($operation.Kind -eq 'Package') { $operation = Resolve-RideLifecycleSelection -Operation $operation -Removal }
      if ($target -notin $operation.SupportedTargets) { continue }
      $current = Get-RideCurrentState -Operation $operation
      $defaults = $operation.TargetDefaults[$target]
      if ($operation.Kind -eq 'PowerSetting') {
        $defaultValue = $defaults.DefaultValue
        $matchesDefault = $null
      }
      elseif ($operation.Kind -eq 'ProfileSetting') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults -and $current.Available) { $current.State -eq $defaultValue } else { $null }
      }
      elseif ($operation.Kind -in @('Package', 'DefenderExclusion', 'ShellFolder')) {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults) { (-not $current.Present) -eq ($defaultValue -eq 'Absent') } else { $null }
      }
      elseif ($operation.Kind -eq 'BackgroundAppOverrides') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults) { -not $current.Present } else { $null }
      }
      elseif ($operation.Kind -eq 'WindowsService') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults -and $defaultValue -notin @('PlatformDefined', 'Platform-defined', '<platform-defined>')) { (Get-RideCurrentValueText -Operation $operation -CurrentState $current) -eq $defaultValue } else { $null }
      }
      elseif ($operation.Kind -eq 'BootConfiguration') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults -and $defaultValue -notin @('PlatformDefined', 'Platform-defined', '<platform-defined>')) { -not $current.Exists } else { $null }
      }
      elseif ($operation.Kind -eq 'NetworkProfile') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = $null
      }
      elseif ($operation.Kind -in @('RegistryKeySet', 'RegistryValueSet', 'ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = $null
      }
      else {
        $defaultValue = if (-not $defaults) {
          '<not declared>'
        }
        elseif ($null -eq $defaults.DefaultValueExists) {
          '<platform-defined>'
        }
        elseif ($defaults.DefaultValueExists) {
          ConvertTo-RideDisplayValue -Value $defaults.DefaultValue
        }
        else {
          '<unset>'
        }
        $matchesDefault = if ($defaults) {
          if ($null -eq $defaults.DefaultValueExists) {
            $null
          }
          elseif ($defaults.DefaultValueExists) {
            $current.Exists -and $current.ValueType -eq $operation.ValueType -and $current.Value -eq $defaults.DefaultValue
          }
          else {
            -not $current.Exists
          }
        }
        else {
          $null
        }
      }
      $presentation = Get-RideSettingPresentation -Operation $operation -IncludeExecutionIdentity
      if ($operation.Kind -eq 'FirewallProfile') { $presentation.EffectivePolicy = Get-RideFirewallEffectivePolicyText $current }
      $rows.Add([pscustomobject]@{
        Id = $operation.Id
        Name = $operation.Name
        Scope = $operation.Scope
        RequiresAdmin = $operation.RequiresAdmin
        AppliesTo = $presentation.AppliesTo
        Behavior = $presentation.Behavior
        GuiEffect = $presentation.GuiEffect
        GuiPath = $presentation.GuiPath
        Requirements = $presentation.Requirements
        OtherSupportedChoices = $presentation.OtherSupportedChoices
        EffectivePolicy = $presentation.EffectivePolicy
        ExecutionIdentity = $presentation.ExecutionIdentity
        DefaultValue = $defaultValue
        EffectiveDefault = if ($defaults) { $defaults.EffectiveDefault } else { '<not declared>' }
        MatchesDefault = $matchesDefault
        CurrentState = Get-RideCurrentStateName -Operation $operation -CurrentState $current
        CurrentValue = Get-RideCurrentValueText -Operation $operation -CurrentState $current
        CurrentValueType = if ($operation.Kind -eq 'RegistryValue') { if ($current.Exists) { $current.ValueType } else { '<unset>' } } elseif ($operation.Kind -eq 'RegistryValueSet') { 'Coordinated registry values' } elseif ($operation.Kind -eq 'PowerSetting') { 'Power setting index' } elseif ($operation.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } elseif ($operation.Kind -eq 'WindowsService') { 'Service configuration' } elseif ($operation.Kind -eq 'BackgroundAppOverrides') { 'Per-app registry values' } elseif ($operation.Kind -eq 'BootConfiguration') { 'Boot configuration' } elseif ($operation.Kind -eq 'NetworkProfile') { 'Connection profiles' } elseif ($operation.Kind -eq 'RegistryKeySet') { 'Registry key set' } elseif ($operation.Kind -eq 'ShellFolder') { 'Desktop Shell folder' } elseif ($operation.Kind -eq 'ProfileSetting') { 'PowerShell startup profile setting' } elseif ($operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) { $operation.Kind } else { 'Package' }
      })
    }
  }
  if ($rows.Count -eq 0) { throw "No operations matched status view '$View' for the selected target and profile." }
  $rows.ToArray()
}

function Restore-RideRun {
  <#
  .SYNOPSIS
    Restore captured pre-change state for a saved run.

  .DESCRIPTION
    Validates hexadecimal run identity, scopes, target support, and elevation. Uses ShouldProcess
    before each restore. Captured settings restore prior data/presence; packages may reinstall the
    latest upstream release, with a warning when exact prior version recovery is unavailable.

  .PARAMETER RunId
    32 hexadecimal characters identifying a saved run; machine-scoped records require elevation.

  .PARAMETER GitHubAuthentication
    Anonymous (default) or explicit PAT for GitHub release discovery only.

  .PARAMETER GitHubCredentialReference
    Nonsecret enrolled reference required with PAT. Resolved only during acquisition.

  .EXAMPLE
    Get-Help Restore-RideRun -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.String. Per-operation restoration messages.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
  param([Parameter(Mandatory = $true)][string] $RunId, [ValidateSet('Anonymous','PAT')][string] $GitHubAuthentication = 'Anonymous', [string] $GitHubCredentialReference)
  if ($RunId -notmatch '^[a-fA-F0-9]{32}$') { throw 'Run ID must be a 32-character hexadecimal value.' }
  $roots = @((Get-RideStateRoot -Scope 'User'))
  if (Test-RideAdministrator) { $roots += (Get-RideStateRoot -Scope 'Machine') }
  $records = foreach ($root in $roots) {
    $directory = Join-Path $root $RunId
    if (Test-Path -LiteralPath $directory) { Get-ChildItem -LiteralPath $directory -Filter '*.json' -File | Where-Object { $_.Name -ne '_manifest.json' } }
  }
  if (-not $records) {
    if (-not (Test-RideAdministrator)) { throw "No user-scoped saved state was found for run '$RunId'. If it changed machine state, run restore from an elevated PowerShell session." }
    throw "No saved state was found for run '$RunId'."
  }
  $manifestPath = Join-Path (Get-RideStateRoot -Scope User) (Join-Path $RunId '_manifest.json')
  if (Test-Path -LiteralPath $manifestPath) {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ('Machine' -in $manifest.Scopes -and -not (Test-RideAdministrator)) {
      throw 'This run contains machine-scoped state and must be restored from an elevated PowerShell session.'
    }
  }
  $loadedRecords = @($records | ForEach-Object {
    [pscustomobject]@{ File = $_; Record = (Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json) }
  })
  if (($loadedRecords | Where-Object { $_.Record.Scope -eq 'Machine' }).Count -gt 0 -and -not (Test-RideAdministrator)) {
    throw 'This run includes machine-scoped state and must be restored from an elevated PowerShell session.'
  }
  $catalog = Get-RideCatalog
  $target = Get-RidePlatform
  # Validate every saved operation before the first restore can change anything.
  foreach ($entry in $loadedRecords) {
    $record = $entry.Record
    $operation = $catalog.Operations | Where-Object { $_.Id -eq $record.OperationId } | Select-Object -First 1
    if ($record.SchemaVersion -notin @(1, 2, 3)) { throw "Unsupported saved-state schema for '$($record.OperationId)'." }
    $recoveryHint = if ($record.RecoveryUri -and [Uri]::IsWellFormedUriString([string]$record.RecoveryUri, [UriKind]::Absolute) -and ([Uri]$record.RecoveryUri).Scheme -eq 'https') { " Recovery information: $($record.RecoveryUri)" } else { '' }
    if (-not $operation) { throw "Saved state refers to unknown operation '$($record.OperationId)'. Supply its original library with -Library before restoring.$recoveryHint" }
    if ($record.Library -or $operation.Library) {
      if ($record.SchemaVersion -notin @(2, 3) -or -not $record.Library -or -not $operation.Library) { throw "Missing library recovery identity for '$($record.OperationId)'. Select the original library." }
      foreach ($field in @('Id', 'Version', 'EngineApiVersion', 'CatalogSha256', 'Handler', 'SnapshotSchemaVersion')) {
        if ($null -eq $record.Library.$field -or $record.Library.$field -cne $operation.Library[$field]) { throw "Library recovery mismatch ($field) for '$($record.OperationId)'. Select the original library version and unchanged catalog with -Library; captured state is retained.$recoveryHint" }
      }
    }
    if ($record.SchemaVersion -eq 3) {
      if (-not $record.PackageSelection -or $record.Kind -ne 'Package') { throw 'Missing saved package selection.' }
      $saved = @{}; foreach ($property in $record.PackageSelection.PSObject.Properties) { $saved[$property.Name] = $property.Value }
      if ($saved.Id -ne $operation.Id -or $saved.Kind -ne 'Package' -or -not $saved.SelectedVariant -or $saved.Scope -notin @('Machine', 'User')) { throw 'Invalid saved package selection.' }
      $operation = $saved
      if ($operation.InstallerType -eq 'Portable') {
        $expectedBackup = Join-Path (Get-RideStateRoot -Scope $operation.Scope) (Join-Path $RunId ($operation.Id + '.files'))
        if ([IO.Path]::GetFullPath($record.Snapshot.BackupDirectory) -ne [IO.Path]::GetFullPath($expectedBackup)) { throw 'Portable backup is outside its saved run.' }
        Restore-RidePortableSnapshot -Operation $operation -Snapshot $record.Snapshot -ValidateOnly
      }
    }
    if ($operation.RequiresUnelevatedUser -and -not $WhatIfPreference -and (Test-RideAdministrator)) { throw 'Restore this current-user package from a non-elevated PowerShell session.' }
    if ($record.Kind -ne $operation.Kind -or $record.Scope -ne $operation.Scope) { throw "Saved operation contract changed for '$($record.OperationId)'." }
    if ($operation.Kind -eq 'ProfileSetting') { Restore-RideProfileSettingState -Operation $operation -Snapshot $record.Snapshot -ValidateOnly }
    if ($target -notin $operation.SupportedTargets) { throw "Cannot restore '$($operation.Id)' on unsupported target $target." }
    if ($operation.RequiresDesktopExperience -and $target -like 'Windows Server*' -and (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType -ErrorAction Stop).InstallationType -ne 'Server') { throw "Cannot restore '$($operation.Id)' without Windows Server Desktop Experience." }
  }
  foreach ($entry in $loadedRecords) {
    $file = $entry.File
    $record = $entry.Record
    $operation = $catalog.Operations | Where-Object { $_.Id -eq $record.OperationId } | Select-Object -First 1
    if (-not $operation) { throw "Saved state refers to unknown operation '$($record.OperationId)'." }
    if ($record.SchemaVersion -eq 3) { $operation = @{}; foreach ($property in $record.PackageSelection.PSObject.Properties) { $operation[$property.Name] = $property.Value } }
    if (-not $PSCmdlet.ShouldProcess($operation.Name, 'Restore previously recorded state')) { continue }
    if ($operation.Kind -eq 'RegistryValue') {
      Restore-RideSettingState -Operation $operation -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'RegistryValueSet') {
      Restore-RideRegistryValueSetState -Operation $operation -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'LocalPasswordMaximumAge') { Restore-RideLocalPasswordAgeState -Operation $operation -Snapshot $record.Snapshot }
    elseif ($operation.Kind -eq 'OwnedPowerPlan') { Restore-RideOwnedPowerPlanState -Operation $operation -Snapshot $record.Snapshot -OwnershipRoot (Join-Path (Get-RideStateRoot -Scope Machine) 'OwnedPowerPlans') }
    elseif ($operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) { Restore-RideManagedSettingState -Operation $operation -Snapshot $record.Snapshot }
    elseif ($operation.InstallerType -eq 'Portable') {
      Restore-RidePortableSnapshot -Operation $operation -Snapshot $record.Snapshot
      Save-RidePackageSelectionIndex -Operation $operation
    }
    elseif ($operation.Kind -eq 'Package') {
      $currentlyInstalled = (Get-RideInstalledPackage -Operation $operation).Present
      if ($record.Snapshot.Present -and -not $currentlyInstalled) {
        Write-Warning "$($operation.Name) was previously installed, but exact package version recovery is unavailable; reinstalling the catalog's declared installer."
        if ($record.RecoveryUri) { Write-Warning "Recovery information: $($record.RecoveryUri)" }
        $cache = Join-Path (Get-RideStateRoot -Scope $operation.Scope) 'Cache'
        Install-RidePackage -Operation $operation -CacheDirectory $cache -GitHubAuthentication $GitHubAuthentication -GitHubCredentialReference $GitHubCredentialReference
      }
      elseif (-not $record.Snapshot.Present -and $currentlyInstalled) {
        Uninstall-RidePackage -Operation $operation
      }
    }
    elseif ($operation.Kind -eq 'DefenderExclusion') {
      Restore-RideDefenderExclusionState -Operation $operation -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'WindowsService') {
      Restore-RideWindowsServiceState -Operation $operation -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'BackgroundAppOverrides') {
      Restore-RideBackgroundAppOverrides -Operation $operation -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'BootConfiguration') {
      Restore-RideBootConfigurationState -Operation $operation -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'NetworkProfile') {
      Restore-RideNetworkProfileState -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'RegistryKeySet') {
      Restore-RideRegistryKeySetState -Trees @($record.Snapshot.Trees)
    }
    elseif ($operation.Kind -eq 'PowerSetting') {
      Restore-RidePowerSettingState -Operation $operation -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'ShellFolder') {
      Restore-RideShellFolderState -Operation $operation -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'ProfileSetting') {
      Restore-RideProfileSettingState -Operation $operation -Snapshot $record.Snapshot -Confirm:$false
    }
    Write-Output "Restored prior state: $($operation.Id)"
  }
}

# Complete the same resolved metadata used by execution without invoking handlers.
Register-ArgumentCompleter -CommandName Get-RideSingleOperationPlan, Save-RidePackage, Show-RideOperation -ParameterName Variant -ScriptBlock {
  param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
  try {
    & (Get-Module RIDE.Engine) {
      param($id, $word)
      $catalog = if ($script:RideLibraryContext) { $script:RideLibraryContext.Catalog } else { Import-RideCatalogData -Path $script:RideCatalogPath }
      $package = $catalog.Operations | Where-Object { $_.Id -eq $id -and $_.Kind -eq 'Package' } | Select-Object -First 1
      if (-not $package) { return }
      $names = if ($package.Variants) { @($package.Variants.Keys) } else { @('installed') }
      foreach ($name in $names | Sort-Object -Unique) {
        if ($name.StartsWith([string]$word, [StringComparison]::OrdinalIgnoreCase)) { [Management.Automation.CompletionResult]::new($name, $name, 'ParameterValue', $name) }
      }
    } $fakeBoundParameters.Id $wordToComplete
  } catch { }
}

Export-ModuleMember -Function Set-RideLibraryContext, Get-RideCatalog, Get-RideOperation, Get-RideProfile, Get-RidePlan, Get-RideSingleOperationPlan, Save-RidePackage, Invoke-RidePlan, Show-RideCatalog, Show-RideOperation, Show-RidePlan, Get-RideStatus, Get-RideCurrentState, Test-RideDesiredState, Get-RidePlatform, Restore-RideRun
