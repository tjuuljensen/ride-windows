$script:RideRoot = Split-Path -Parent $PSScriptRoot
$script:RideCatalogPath = Join-Path $script:RideRoot 'catalog/operations.psd1'
$script:RideSettingsModule = Join-Path $PSScriptRoot 'RIDE-Settings.psm1'
$script:RidePackagesModule = Join-Path $PSScriptRoot 'RIDE-Packages.psm1'
$script:RideDefenderModule = Join-Path $PSScriptRoot 'RIDE-Defender.psm1'
Import-Module $script:RideSettingsModule -Force -ErrorAction Stop
Import-Module $script:RidePackagesModule -Force -ErrorAction Stop
Import-Module $script:RideDefenderModule -Force -ErrorAction Stop

function Get-RideCatalog {
  Import-PowerShellDataFile -Path $script:RideCatalogPath
}

function Get-RideOperation {
  param([Parameter(Mandatory = $true)][string] $Id)
  $catalog = Get-RideCatalog
  $operation = $catalog.Operations | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
  if ($operation) { return $operation }
  $group = $catalog.Groups | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
  if ($group) { return $group }
  throw "Unknown operation or group ID: $Id"
}

function Get-RideProfile {
  param([string] $Path = (Join-Path $script:RideRoot 'profiles/default.psd1'))
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Profile file not found: $Path" }
  $profile = Import-PowerShellDataFile -Path $Path
  if ($profile.SchemaVersion -ne 1) { throw "Unsupported profile schema version: $($profile.SchemaVersion)" }
  if (-not $profile.Operations) { throw "Profile '$($profile.Name)' has no operations." }
  $profile
}

function Get-RidePlatform {
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
  $State
}

function Get-RideCurrentState {
  param([Parameter(Mandatory = $true)][hashtable] $Operation)
  switch ($Operation.Handler) {
    'RegistryValue' { return Get-RideSettingState -Operation $Operation }
    'Package' { return Get-RideInstalledPackage -Operation $Operation }
    'DefenderExclusion' { return Get-RideDefenderExclusionState -Operation $Operation }
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
  if ($Operation.Kind -eq 'DefenderExclusion') {
    if (-not $CurrentState.Present) { return '<absent>' }
    return $CurrentState.Path
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
  $desiredPresent = (Get-RideOperationValue -Operation $Operation -State $State) -eq 'Present'
  return ([bool]$CurrentState.Present -eq $desiredPresent)
}

function Get-RideCurrentStateName {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $CurrentState
  )

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
  param(
    [Parameter(Mandatory = $true)][hashtable] $Profile,
    [ValidateSet('Apply', 'Remove')][string] $Action = 'Apply'
  )
  $plan = @(Expand-RideProfileOperations -Profile $Profile -Action $Action)
  foreach ($item in $plan) {
    if (-not $item.State) { throw "No state was selected for '$($item.Operation.Id)'." }
    $null = Get-RideOperationValue -Operation $item.Operation -State $item.State
    if ($Action -eq 'Apply' -and $item.Operation.Kind -in @('RegistryValue', 'DefenderExclusion') -and 'Set' -notin $item.Operation.Actions) { throw "'$($item.Operation.Id)' does not support set." }
    if ($item.Operation.Kind -eq 'Package' -and $item.State -eq 'Present' -and 'Install' -notin $item.Operation.Actions) { throw "'$($item.Operation.Id)' does not support install." }
    if ($item.Operation.Kind -eq 'Package' -and $item.State -eq 'Absent' -and 'Uninstall' -notin $item.Operation.Actions) { throw "'$($item.Operation.Id)' does not support uninstall." }
  }
  $plan
}

function Get-RideSingleOperationPlan {
  param(
    [Parameter(Mandatory = $true)][string] $Id,
    [ValidateSet('Set', 'Unset', 'Install', 'Remove')][string] $Action,
    [string] $State
  )

  $operation = Get-RideOperation -Id $Id
  if (-not $operation.ContainsKey('Kind')) { throw "Direct actions require an operation ID, not a group ID: $Id" }
  switch ($Action) {
    'Set' {
      if ($operation.Kind -notin @('RegistryValue', 'DefenderExclusion')) { throw "'set' requires a Windows setting ID; '$Id' is a $($operation.Kind) operation." }
      if (-not $State) {
        $availableStates = if ($operation.Kind -eq 'RegistryValue') { $operation.States.Keys -join ', ' } else { 'Present, Absent' }
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

function Invoke-RidePlan {
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
    '^groups?$' { @($rows | Where-Object Type -eq 'Group'); break }
    '^settings?$' { @($rows | Where-Object { $_.Type -eq 'Operation' -and $_.Kind -in @('RegistryValue', 'DefenderExclusion') }); break }
    default {
      $categoryPart = [regex]::Escape($viewKey)
      @($rows | Where-Object {
        $_.Type -ne 'Profile' -and
        ($_.Category -match "(?i)^$categoryPart(?:\s|/|$)" -or $_.Category -match "(?i)/\s*$categoryPart$")
      })
    }
  }
  if (-not $filtered -or @($filtered).Count -eq 0) { throw "Unknown or empty list view '$View'. Use all, profiles, packages, groups, settings, or a catalog category such as windows, explorer, or security." }
  $filtered | Sort-Object Type, Category, Name
}

function Show-RideOperation {
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
        CurrentValueType = if ($operation.Kind -eq 'RegistryValue') { $current.ValueType } elseif ($operation.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } else { 'Package' }
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
  $details.CurrentValueType = if ($entry.Kind -eq 'RegistryValue') { $current.ValueType } elseif ($entry.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } else { 'Package' }
  if ($entry.Kind -eq 'RegistryValue') {
    $baselineValue = Get-RideOperationValue -Operation $entry -State $entry.BaselineState
    $details.BaselineValue = ConvertTo-RideDisplayValue -Value $baselineValue
  }
  elseif ($entry.Kind -eq 'DefenderExclusion') {
    $details.Present = [bool]$current.Present
  }
  else {
    $details.Installed = [bool]$current.Present
  }
  [pscustomobject]$details | Format-List
}

function Show-RidePlan {
  param([Parameter(Mandatory = $true)][object[]] $Plan)
  $rows = foreach ($item in $Plan) {
    $current = Get-RideCurrentState -Operation $item.Operation
    $desiredValue = if ($item.Operation.Kind -eq 'RegistryValue') {
      ConvertTo-RideDisplayValue -Value (Get-RideOperationValue -Operation $item.Operation -State $item.State)
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
    '^settings?$' { return ($Operation.Kind -in @('RegistryValue', 'DefenderExclusion')) }
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
        CurrentValueType = if ($item.Operation.Kind -eq 'RegistryValue') { if ($current.Exists) { $current.ValueType } else { '<unset>' } } elseif ($item.Operation.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } else { 'Package' }
      })
    }
  }
  else {
    $target = Get-RidePlatform
    foreach ($operation in $catalog.Operations) {
      if ($target -notin $operation.SupportedTargets) { continue }
      if (-not (Test-RideStatusView -Operation $operation -View $View -Catalog $catalog)) { continue }
      $current = Get-RideCurrentState -Operation $operation
      $defaults = $operation.TargetDefaults[$target]
      if ($operation.Kind -in @('Package', 'DefenderExclusion')) {
        $defaultValue = if ($defaults) { $defaults.DefaultValue } else { '<not declared>' }
        $matchesDefault = if ($defaults) { (-not $current.Present) -eq ($defaultValue -eq 'Absent') } else { $null }
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
        CurrentValueType = if ($operation.Kind -eq 'RegistryValue') { if ($current.Exists) { $current.ValueType } else { '<unset>' } } elseif ($operation.Kind -eq 'DefenderExclusion') { 'Defender exclusion' } else { 'Package' }
      })
    }
  }
  if ($rows.Count -eq 0) { throw "No operations matched status view '$View' for the selected target and profile." }
  $rows.ToArray()
}

function Restore-RideRun {
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
    Write-Output "Restored prior state: $($operation.Id)"
  }
}

Export-ModuleMember -Function Get-RideCatalog, Get-RideOperation, Get-RideProfile, Get-RidePlan, Get-RideSingleOperationPlan, Invoke-RidePlan, Show-RideCatalog, Show-RideOperation, Show-RidePlan, Get-RideStatus, Get-RideCurrentState, Test-RideDesiredState, Get-RidePlatform, Restore-RideRun
