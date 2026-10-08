[CmdletBinding()]
param([string] $Root = '')

$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$errors = New-Object System.Collections.Generic.List[string]

function Add-Error([string] $Message) { $errors.Add($Message) }

$catalogPath = Join-Path $Root 'catalog/operations.psd1'
$profilePaths = @(Get-ChildItem -LiteralPath (Join-Path $Root 'profiles') -Filter '*.psd1' -File)
$catalog = Import-PowerShellDataFile -Path $catalogPath
if ($catalog.SchemaVersion -ne 1) { Add-Error 'Catalog must declare SchemaVersion 1.' }

$ids = @{}
foreach ($operation in $catalog.Operations) {
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
    if ($operation.Kind -in @('Package', 'DefenderExclusion') -and -not $defaults.ContainsKey('DefaultValue')) {
      Add-Error "Operation '$($operation.Id)' is missing a literal default for '$target'."
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
    if ($operation.Handler -ne 'Package') { Add-Error "No matching handler for $($operation.Id)" }
    foreach ($field in @('PackageId', 'InstallerType', 'DownloadUri', 'InstallerArguments', 'UninstallerArguments', 'DisplayNamePattern')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Package operation is missing '$field': $($operation.Id)" }
    }
    if (-not $operation.ContainsKey('ProductUri')) { Add-Error "Package operation is missing product information URI: $($operation.Id)" }
    elseif (-not [Uri]::IsWellFormedUriString([string]$operation.ProductUri, [UriKind]::Absolute) -or ([Uri]$operation.ProductUri).Scheme -ne 'https') {
      Add-Error "Package operation must use an absolute HTTPS product URI: $($operation.Id)"
    }
    if ('Install' -notin $operation.Actions -or 'Uninstall' -notin $operation.Actions) { Add-Error "Package lifecycle must include install and uninstall: $($operation.Id)" }
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
    if ($operation -and $operation.Kind -eq 'WindowsService' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid service state for '$($selection.Id)'" }
    if ($operation -and $operation.Kind -eq 'BackgroundAppOverrides' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid background app state for '$($selection.Id)'" }
    if ($operation -and $operation.Kind -eq 'BootConfiguration' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid boot configuration state for '$($selection.Id)'" }
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
