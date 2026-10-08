<#
.SYNOPSIS
  Load the RIDE catalog, build plans, and manage operation lifecycles.

.DESCRIPTION
  Imports focused handlers, expands profiles/groups, checks supported targets, inspects state,
  executes ShouldProcess-gated plans, captures per-scope pre-change snapshots/manifests, and
  restores saved runs. Package restoration may use the latest release rather than the exact previous
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
  machine scope, LocalApplicationData/RIDE/State for user scope, and artifact observations.
  Recovery: Restore-RideRun recovers captured settings/presence. Read catalog rollback limits before
  applying packages or grouped changes.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

.LINK
  docs/OPERATIONS.md

.LINK
  docs/models/script-repository-model.md

#>


$script:ModuleVersion = '0.1.0'

$script:RideRoot = Split-Path -Parent $PSScriptRoot
$script:RideCatalogPath = Join-Path $script:RideRoot 'catalog/operations.psd1'
$script:RideSettingsModule = Join-Path $PSScriptRoot 'RIDE-Settings.psm1'
$script:RidePackagesModule = Join-Path $PSScriptRoot 'RIDE-Packages.psm1'
$script:RideDefenderModule = Join-Path $PSScriptRoot 'RIDE-Defender.psm1'
$script:RideServicesModule = Join-Path $PSScriptRoot 'RIDE-Services.psm1'
$script:RideBackgroundAppsModule = Join-Path $PSScriptRoot 'RIDE-BackgroundApps.psm1'
$script:RideBootConfigurationModule = Join-Path $PSScriptRoot 'RIDE-BootConfiguration.psm1'
$script:RideNetworkProfilesModule = Join-Path $PSScriptRoot 'RIDE-NetworkProfiles.psm1'
$script:RideRegistryKeySetModule = Join-Path $PSScriptRoot 'RIDE-RegistryKeySet.psm1'
Import-Module $script:RideSettingsModule -Force -ErrorAction Stop
Import-Module $script:RidePackagesModule -Force -ErrorAction Stop
Import-Module $script:RideDefenderModule -Force -ErrorAction Stop
Import-Module $script:RideServicesModule -Force -ErrorAction Stop
Import-Module $script:RideBackgroundAppsModule -Force -ErrorAction Stop
Import-Module $script:RideBootConfigurationModule -Force -ErrorAction Stop
Import-Module $script:RideNetworkProfilesModule -Force -ErrorAction Stop
Import-Module $script:RideRegistryKeySetModule -Force -ErrorAction Stop

function Get-RideCatalog {
  <#
  .SYNOPSIS
    Read the authoritative RIDE catalog data.

  .DESCRIPTION
    Imports catalog/operations.psd1 as data. Does not inspect or change Windows state.

  .EXAMPLE
    Get-RideCatalog

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Collections.Hashtable. Catalog SchemaVersion, Operations, and Groups.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  Import-PowerShellDataFile -Path $script:RideCatalogPath
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
  $profile = Import-PowerShellDataFile -Path $Path
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
      if ($Action -eq 'Remove' -and $entry.Kind -notin @('Package', 'DefenderExclusion')) { continue }
      $state = if ($Action -eq 'Remove') { 'Absent' } elseif ($selection.ContainsKey('State')) { $selection.State } else { $null }
      if ($entry.Kind -eq 'RegistryValue' -and $state -eq 'Baseline') { $state = $entry.BaselineState }
      $expanded.Add([pscustomobject]@{ Operation = $entry; State = $state })
      continue
    }

    $group = $catalog.Groups | Where-Object { $_.Id -eq $selection.Id } | Select-Object -First 1
    if (-not $group) { throw "Profile references unknown operation or group: $($selection.Id)" }
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
      if (-not $member) { throw "Group '$($group.Id)' references unknown operation '$memberId'." }
      $expanded.Add([pscustomobject]@{ Operation = $member; State = if ($member.Kind -in @('Package', 'DefenderExclusion')) { $groupState } else { $null } })
    }
  }

  $expanded.ToArray()
}

function Get-RideOperationValue {
  param([hashtable] $Operation, [string] $State)
  if ($Operation.Kind -eq 'RegistryValue') {
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
    Selects registry, package, Defender, service, background-app, BCD, network, or registry-tree
    inspection. Download-only artifacts return a synthetic absence record. No apply/remove handlers
    are invoked.

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
    'RegistryValue' { return Get-RideSettingState -Operation $Operation }
    'Package' { return Get-RideInstalledPackage -Operation $Operation }
    'Artifact' { return [pscustomobject]@{ Present = $false; DisplayName = 'Download-only artifact'; DisplayVersion = $null } }
    'DefenderExclusion' { return Get-RideDefenderExclusionState -Operation $Operation }
    'WindowsService' { return Get-RideWindowsServiceState -Operation $Operation }
    'BackgroundAppOverrides' { return Get-RideBackgroundAppOverrides -Operation $Operation }
    'BootConfiguration' { return Get-RideBootConfigurationState -Operation $Operation }
    'NetworkProfile' { return Get-RideNetworkProfileState -Operation $Operation }
    'RegistryKeySet' { return Get-RideRegistryKeyTreeState -Operation $Operation }
    default { throw "No handler is registered for '$($Operation.Handler)'." }
  }
}

function ConvertTo-RideDisplayValue {
  param($Value)
  if ($null -eq $Value) { return '<unset>' }
  if ($Value -is [array]) { return ($Value -join ', ') }
  [string]$Value
}

function Get-RideCurrentValueText {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $CurrentState
  )

  if ($Operation.Kind -eq 'RegistryValue') {
    if (-not $CurrentState.Exists) { return '<unset>' }
    return ConvertTo-RideDisplayValue -Value $CurrentState.Value
  }
  if ($Operation.Kind -eq 'Artifact') { return 'Download only; no configuration is applied' }
  if ($Operation.Kind -eq 'DefenderExclusion') {
    if (-not $CurrentState.Present) { return '<absent>' }
    return $CurrentState.Path
  }
  if ($Operation.Kind -eq 'WindowsService') { return '{0} / {1}' -f $CurrentState.StartupType, $CurrentState.Status }
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

  if ($Operation.Kind -eq 'RegistryValue') {
    $desired = Get-RideOperationValue -Operation $Operation -State $State
    if ($null -eq $desired) { return (-not $CurrentState.Exists) }
    return ($CurrentState.Exists -and $CurrentState.ValueType -eq $Operation.ValueType -and $CurrentState.Value -eq $desired)
  }
  if ($Operation.Kind -eq 'WindowsService') {
    $desired = Get-RideOperationValue -Operation $Operation -State $State
    return ($CurrentState.StartupType -eq $desired.StartupType -and $CurrentState.Status -eq $desired.Status)
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
  return ([bool]$CurrentState.Present -eq $desiredPresent)
}

function Get-RideCurrentStateName {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $CurrentState
  )

  if ($Operation.Kind -eq 'WindowsService') {
    foreach ($stateName in $Operation.States.Keys) {
      $desired = $Operation.States[$stateName]
      if ($CurrentState.StartupType -eq $desired.StartupType -and $CurrentState.Status -eq $desired.Status) { return $stateName }
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
  if ($Operation.Kind -in @('Package', 'DefenderExclusion')) {
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
  param([string] $RunId, [hashtable] $Operation, $CurrentState)
  $key = $null
  if ($Operation.Kind -eq 'RegistryValue') {
    $key = Get-Item -LiteralPath $Operation.RegistryPath -ErrorAction SilentlyContinue
  }
  $snapshot = if ($Operation.Kind -eq 'RegistryValue') {
    [ordered]@{
      Exists = [bool]$CurrentState.Exists
      KeyExisted = [bool]($null -ne $key)
      Value = $CurrentState.Value
      ValueType = $CurrentState.ValueType
    }
  }
  elseif ($Operation.Kind -eq 'DefenderExclusion') {
    [ordered]@{ Present = [bool]$CurrentState.Present; Path = $CurrentState.Path }
  }
  elseif ($Operation.Kind -eq 'WindowsService') {
    [ordered]@{ StartupType = $CurrentState.StartupType; Status = $CurrentState.Status }
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
  $root = Initialize-RideStateRoot -Scope $Operation.Scope
  $fileName = ($Operation.Id -replace '[^a-zA-Z0-9._-]', '_') + '.json'
  $path = Join-Path $root (Join-Path $RunId $fileName)
  New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
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
    if ($target -notin $item.Operation.SupportedTargets) {
      throw "'$($item.Operation.Id)' does not support $target. Supported: $($item.Operation.SupportedTargets -join ', ')."
    }
  }
  if (-not $WhatIfPreference -and ($Plan | Where-Object { $_.Operation.RequiresAdmin }).Count -gt 0 -and -not (Test-RideAdministrator)) {
    throw 'This plan contains machine operations and must be run from an elevated PowerShell session.'
  }
}

function Get-RidePlan {
  <#
  .SYNOPSIS
    Expand and validate desired operation states without applying them.

  .DESCRIPTION
    Expands ordered group members, reverses removal order, resolves baseline states, and validates
    declared lifecycle actions. Does not inspect live Windows state or write snapshots.

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
    if ($Action -eq 'Apply' -and $item.Operation.Kind -in @('RegistryValue', 'DefenderExclusion', 'WindowsService', 'BackgroundAppOverrides', 'BootConfiguration', 'NetworkProfile', 'RegistryKeySet') -and 'Set' -notin $item.Operation.Actions) { throw "'$($item.Operation.Id)' does not support set." }
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
    [string] $State
  )

  $operation = Get-RideOperation -Id $Id
  if (-not $operation.ContainsKey('Kind')) { throw "Direct actions require an operation ID, not a group ID: $Id" }
  switch ($Action) {
    'Set' {
      if ($operation.Kind -notin @('RegistryValue', 'DefenderExclusion', 'WindowsService', 'BackgroundAppOverrides', 'BootConfiguration', 'NetworkProfile', 'RegistryKeySet')) { throw "'set' requires a Windows setting ID; '$Id' is a $($operation.Kind) operation." }
      if (-not $State) {
        $availableStates = if ($operation.Kind -in @('RegistryValue', 'WindowsService', 'BackgroundAppOverrides', 'BootConfiguration', 'NetworkProfile', 'RegistryKeySet')) { $operation.States.Keys -join ', ' } else { 'Present, Absent' }
        throw "The set command requires -State. Available states: $availableStates."
      }
      if ('Set' -notin $operation.Actions) { throw "'$Id' does not support setting a value." }
    }
    'Unset' {
      if ($operation.Kind -eq 'DefenderExclusion') {
        $State = 'Absent'
      }
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

  .PARAMETER Destination
    Artifact destination root; defaults to the user RIDE state root Artifacts directory.

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
    [string] $Destination = (Join-Path (Get-RideStateRoot -Scope User) 'Artifacts')
  )

  $operation = Get-RideOperation -Id $Id
  if ($operation.Kind -notin @('Package', 'Artifact')) { throw "The download command requires a package or artifact ID; '$Id' is a $($operation.Kind) operation." }
  if ('Download' -notin $operation.Actions) { throw "Catalog item '$Id' does not support download." }
  if ($PSCmdlet.ShouldProcess($operation.Name, "Download latest artifact to '$Destination'")) {
    Save-RidePackageArtifact -Operation $operation -DestinationDirectory $Destination
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
    [Parameter(Mandatory = $true)][object[]] $Plan
  )
  Assert-RidePlanAllowed -Plan $Plan
  $runId = [guid]::NewGuid().ToString('N')
  $savedOperationIds = New-Object System.Collections.Generic.List[string]
  $completedOperationIds = New-Object System.Collections.Generic.List[string]
  $manifestSaved = $false
  foreach ($item in $Plan) {
    $operation = $item.Operation
    $before = Get-RideCurrentState -Operation $operation
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
        Save-RideOperationSnapshot -RunId $runId -Operation $operation -CurrentState $before
        $savedOperationIds.Add($operation.Id)
        if ($operation.Kind -eq 'RegistryValue') {
          $value = Get-RideOperationValue -Operation $operation -State $item.State
          Set-RideSettingState -Operation $operation -Value $value
        }
        elseif ($operation.Kind -eq 'Package') {
          if ($item.State -eq 'Present') {
            $cache = Join-Path (Get-RideStateRoot -Scope $operation.Scope) 'Cache'
            Install-RidePackage -Operation $operation -CacheDirectory $cache
          }
          else {
            Uninstall-RidePackage -Operation $operation
          }
        }
        elseif ($operation.Kind -eq 'DefenderExclusion') {
          Set-RideDefenderExclusionState -Operation $operation -State $item.State
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
    members/path, and description.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $View = 'all')

  $catalog = Get-RideCatalog
  $rows = New-Object System.Collections.Generic.List[object]
  foreach ($operation in $catalog.Operations) {
    $rows.Add([pscustomobject]@{
      Type = 'Operation'
      Id = $operation.Id
      Name = $operation.Name
      Category = $operation.Category
      Kind = $operation.Kind
      Scope = $operation.Scope
      RequiresAdmin = $operation.RequiresAdmin
      Actions = @($operation.Actions)
      Members = @()
      Path = ''
      Description = $operation.Description
    })
  }
  foreach ($group in $catalog.Groups) {
    $rows.Add([pscustomobject]@{
      Type = 'Group'
      Id = $group.Id
      Name = $group.Name
      Category = $group.Category
      Kind = 'Group'
      Scope = ''
      RequiresAdmin = $null
      Actions = @($group.Actions)
      Members = @($group.Members)
      Path = ''
      Description = $group.Description
    })
  }
  foreach ($profileFile in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../profiles') -Filter '*.psd1' -File) {
    $profile = Import-PowerShellDataFile -Path $profileFile.FullName
    $rows.Add([pscustomobject]@{
      Type = 'Profile'
      Id = [IO.Path]::GetFileNameWithoutExtension($profileFile.Name)
      Name = $profile.Name
      Category = 'Profiles'
      Kind = 'Profile'
      Scope = ''
      RequiresAdmin = $null
      Actions = @()
      Members = @($profile.Operations | ForEach-Object { $_.Id })
      Path = Join-Path 'profiles' $profileFile.Name
      Description = $profile.Description
    })
  }

  $viewKey = $View.ToLowerInvariant()
  $filtered = switch -Regex ($viewKey) {
    '^all$' { $rows; break }
    '^profiles?$' { @($rows | Where-Object Type -eq 'Profile'); break }
    '^packages?$' { @($rows | Where-Object { $_.Type -eq 'Operation' -and $_.Kind -eq 'Package' }); break }
    '^artifacts?$' { @($rows | Where-Object { $_.Type -eq 'Operation' -and $_.Kind -eq 'Artifact' }); break }
    '^groups?$' { @($rows | Where-Object Type -eq 'Group'); break }
    '^settings?$' { @($rows | Where-Object { $_.Type -eq 'Operation' -and $_.Kind -in @('RegistryValue', 'DefenderExclusion', 'WindowsService', 'BackgroundAppOverrides', 'BootConfiguration', 'NetworkProfile', 'RegistryKeySet') }); break }
    default {
      $categoryPart = [regex]::Escape($viewKey)
      @($rows | Where-Object {
        $_.Type -ne 'Profile' -and
        ($_.Category -match "(?i)^$categoryPart(?:\s|/|$)" -or $_.Category -match "(?i)/\s*$categoryPart$")
      })
    }
  }
  if (-not $filtered -or @($filtered).Count -eq 0) { throw "Unknown or empty list view '$View'. Use all, profiles, packages, artifacts, groups, settings, or a catalog category such as windows, explorer, or security." }
  $filtered | Sort-Object Type, Category, Name
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

  param([Parameter(Mandatory = $true)][string] $Id)
  $entry = Get-RideOperation -Id $Id
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
        CurrentValueType = if ($operation.Kind -eq 'RegistryValue') { $current.ValueType } elseif ($operation.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } elseif ($operation.Kind -eq 'WindowsService') { 'Service configuration' } elseif ($operation.Kind -eq 'BackgroundAppOverrides') { 'Per-app registry values' } elseif ($operation.Kind -eq 'BootConfiguration') { 'Boot configuration' } elseif ($operation.Kind -eq 'NetworkProfile') { 'Connection profiles' } elseif ($operation.Kind -eq 'RegistryKeySet') { 'Registry key set' } else { 'Package' }
      }
    }
    $members | Format-Table -AutoSize
    return
  }

  $current = Get-RideCurrentState -Operation $entry
  $details = [ordered]@{}
  foreach ($key in $entry.Keys) {
    if ($key -ne 'States') { $details[$key] = $entry[$key] }
  }
  $details.CurrentValue = Get-RideCurrentValueText -Operation $entry -CurrentState $current
  $details.CurrentValueType = if ($entry.Kind -eq 'RegistryValue') { $current.ValueType } elseif ($entry.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } elseif ($entry.Kind -eq 'WindowsService') { 'Service configuration' } elseif ($entry.Kind -eq 'BackgroundAppOverrides') { 'Per-app registry values' } elseif ($entry.Kind -eq 'BootConfiguration') { 'Boot configuration' } elseif ($entry.Kind -eq 'NetworkProfile') { 'Connection profiles' } elseif ($entry.Kind -eq 'RegistryKeySet') { 'Registry key set' } elseif ($entry.Kind -eq 'Artifact') { 'Download-only artifact' } else { 'Package' }
  if ($entry.Kind -eq 'RegistryValue') {
    $baselineValue = Get-RideOperationValue -Operation $entry -State $entry.BaselineState
    $details.BaselineValue = ConvertTo-RideDisplayValue -Value $baselineValue
  }
  elseif ($entry.Kind -eq 'DefenderExclusion') {
    $details.Present = [bool]$current.Present
  }
  elseif ($entry.Kind -eq 'WindowsService') {
    $details.CurrentState = Get-RideCurrentStateName -Operation $entry -CurrentState $current
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
    $desiredValue = if ($item.Operation.Kind -eq 'RegistryValue') {
      ConvertTo-RideDisplayValue -Value (Get-RideOperationValue -Operation $item.Operation -State $item.State)
    }
    elseif ($item.Operation.Kind -eq 'WindowsService') {
      $desired = Get-RideOperationValue -Operation $item.Operation -State $item.State
      '{0} / {1}' -f $desired.StartupType, $desired.Status
    }
    else {
      $item.State
    }
    [pscustomobject]@{
      Id = $item.Operation.Id
      Name = $item.Operation.Name
      Action = if ($item.Operation.Kind -eq 'Package' -and $item.State -eq 'Absent') { 'Uninstall' } elseif ($item.Operation.Kind -eq 'Package') { 'Install' } else { 'Set' }
      CurrentValue = Get-RideCurrentValueText -Operation $item.Operation -CurrentState $current
      DesiredState = $item.State
      DesiredValue = $desiredValue
      InDesiredState = Test-RideCurrentStateMatch -Operation $item.Operation -State $item.State -CurrentState $current
      Scope = $item.Operation.Scope
      Rollback = $item.Operation.Rollback
    }
  }
  $rows | Format-Table -AutoSize
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
    '^settings?$' { return ($Operation.Kind -in @('RegistryValue', 'DefenderExclusion', 'WindowsService', 'BackgroundAppOverrides', 'BootConfiguration', 'NetworkProfile', 'RegistryKeySet')) }
    '^groups?$' {
      return [bool]($Catalog.Groups | Where-Object { $Operation.Id -in $_.Members } | Select-Object -First 1)
    }
    default {
      $categoryPart = [regex]::Escape($viewKey)
      return [bool]($Operation.Category -match "(?i)^$categoryPart(?:\s|/|$)" -or $Operation.Category -match "(?i)/\s*$categoryPart$")
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
      $desiredValue = if ($item.Operation.Kind -eq 'RegistryValue') {
        ConvertTo-RideDisplayValue -Value (Get-RideOperationValue -Operation $item.Operation -State $item.State)
      }
      elseif ($item.Operation.Kind -eq 'WindowsService') {
        $desired = Get-RideOperationValue -Operation $item.Operation -State $item.State
        '{0} / {1}' -f $desired.StartupType, $desired.Status
      }
      else {
        $item.State
      }
      $rows.Add([pscustomobject]@{
        Id = $item.Operation.Id
        Name = $item.Operation.Name
        DesiredState = $item.State
        DesiredValue = $desiredValue
        InDesiredState = Test-RideCurrentStateMatch -Operation $item.Operation -State $item.State -CurrentState $current
        CurrentState = Get-RideCurrentStateName -Operation $item.Operation -CurrentState $current
        CurrentValue = Get-RideCurrentValueText -Operation $item.Operation -CurrentState $current
        CurrentValueType = if ($item.Operation.Kind -eq 'RegistryValue') { if ($current.Exists) { $current.ValueType } else { '<unset>' } } elseif ($item.Operation.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } elseif ($item.Operation.Kind -eq 'WindowsService') { 'Service configuration' } elseif ($item.Operation.Kind -eq 'BackgroundAppOverrides') { 'Per-app registry values' } elseif ($item.Operation.Kind -eq 'BootConfiguration') { 'Boot configuration' } elseif ($item.Operation.Kind -eq 'NetworkProfile') { 'Connection profiles' } elseif ($item.Operation.Kind -eq 'RegistryKeySet') { 'Registry key set' } else { 'Package' }
      })
    }
  }
  else {
    $target = Get-RidePlatform
  foreach ($operation in $catalog.Operations) {
      if ($operation.Kind -eq 'Artifact') { continue }
      if ($target -notin $operation.SupportedTargets) { continue }
      if (-not (Test-RideStatusView -Operation $operation -View $View -Catalog $catalog)) { continue }
      $current = Get-RideCurrentState -Operation $operation
      $defaults = $operation.TargetDefaults[$target]
      if ($operation.Kind -in @('Package', 'DefenderExclusion')) {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults) { (-not $current.Present) -eq ($defaultValue -eq 'Absent') } else { $null }
      }
      elseif ($operation.Kind -eq 'BackgroundAppOverrides') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults) { -not $current.Present } else { $null }
      }
      elseif ($operation.Kind -eq 'WindowsService') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults) { (Get-RideCurrentValueText -Operation $operation -CurrentState $current) -eq $defaultValue } else { $null }
      }
      elseif ($operation.Kind -eq 'BootConfiguration') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults) { -not $current.Exists } else { $null }
      }
      elseif ($operation.Kind -eq 'NetworkProfile') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = $null
      }
      elseif ($operation.Kind -eq 'RegistryKeySet') {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = $null
      }
      else {
        $defaultValue = if (-not $defaults) {
          '<not declared>'
        }
        elseif ($defaults.DefaultValueExists) {
          ConvertTo-RideDisplayValue -Value $defaults.DefaultValue
        }
        else {
          '<unset>'
        }
        $matchesDefault = if ($defaults) {
          if ($defaults.DefaultValueExists) {
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
      $rows.Add([pscustomobject]@{
        Id = $operation.Id
        Name = $operation.Name
        DefaultValue = $defaultValue
        EffectiveDefault = if ($defaults) { $defaults.EffectiveDefault } else { '<not declared>' }
        MatchesDefault = $matchesDefault
        CurrentState = Get-RideCurrentStateName -Operation $operation -CurrentState $current
        CurrentValue = Get-RideCurrentValueText -Operation $operation -CurrentState $current
        CurrentValueType = if ($operation.Kind -eq 'RegistryValue') { if ($current.Exists) { $current.ValueType } else { '<unset>' } } elseif ($operation.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } elseif ($operation.Kind -eq 'WindowsService') { 'Service configuration' } elseif ($operation.Kind -eq 'BackgroundAppOverrides') { 'Per-app registry values' } elseif ($operation.Kind -eq 'BootConfiguration') { 'Boot configuration' } elseif ($operation.Kind -eq 'NetworkProfile') { 'Connection profiles' } elseif ($operation.Kind -eq 'RegistryKeySet') { 'Registry key set' } else { 'Package' }
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
  param([Parameter(Mandatory = $true)][string] $RunId)
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
  foreach ($entry in $loadedRecords) {
    $file = $entry.File
    $record = $entry.Record
    $operation = $catalog.Operations | Where-Object { $_.Id -eq $record.OperationId } | Select-Object -First 1
    if (-not $operation) { throw "Saved state refers to unknown operation '$($record.OperationId)'." }
    if ($target -notin $operation.SupportedTargets) { throw "Cannot restore '$($operation.Id)' on unsupported target $target." }
    if (-not $PSCmdlet.ShouldProcess($operation.Name, 'Restore previously recorded state')) { continue }
    if ($operation.Kind -eq 'RegistryValue') {
      Restore-RideSettingState -Operation $operation -Snapshot $record.Snapshot
    }
    elseif ($operation.Kind -eq 'Package') {
      $currentlyInstalled = (Get-RideInstalledPackage -Operation $operation).Present
      if ($record.Snapshot.Present -and -not $currentlyInstalled) {
        Write-Warning "$($operation.Name) was previously installed, but exact package version recovery is unavailable; reinstalling the current upstream release."
        $cache = Join-Path (Get-RideStateRoot -Scope $operation.Scope) 'Cache'
        Install-RidePackage -Operation $operation -CacheDirectory $cache
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
    Write-Output "Restored prior state: $($operation.Id)"
  }
}

Export-ModuleMember -Function Get-RideCatalog, Get-RideOperation, Get-RideProfile, Get-RidePlan, Get-RideSingleOperationPlan, Save-RidePackage, Invoke-RidePlan, Show-RideCatalog, Show-RideOperation, Show-RidePlan, Get-RideStatus, Get-RideCurrentState, Test-RideDesiredState, Get-RidePlatform, Restore-RideRun
