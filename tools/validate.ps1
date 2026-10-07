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
