<#
.SYNOPSIS
  Inspect, apply, and restore catalog registry values.

.DESCRIPTION
  Defines focused registry handlers. Get preserves raw value data and type; Set creates/removes
  values; Restore recovers captured data and optionally removes a newly created empty key. Import
  defines commands without reading registry state.

.EXAMPLE
  Import-Module .\modules\RIDE-Settings.psm1
  Import definitions; inspect exported commands with Get-Help before use.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return the types documented in their individual help.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Windows registry provider; elevation for machine-scoped writes.
  File/environment inputs: Catalog RegistryPath, ValueName, ValueType, desired values, and captured
  snapshots.
  Recovery: State-changing handlers are engine-internal: use ride.ps1 preview and captured-run
  restoration. Direct calls bypass ShouldProcess and snapshot capture.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish documented module ownership, version, and exported-command help during this
    walkthrough.
  Supported targets are declared per operation in catalog/operations.psd1. This walkthrough
  validates syntax/help, not Windows state transitions.

.LINK
  docs/models/script-repository-model.md

.LINK
  docs/OPERATIONS.md

#>


$script:ModuleVersion = '0.1.0'

function Get-RideSettingState {
  <#
  .SYNOPSIS
    Capture a registry value without expanding environment variables.

  .DESCRIPTION
    Reads the declared key/value and returns existence, raw data, and registry value kind. Missing
    keys/values return Exists=false. No writes occur.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideSettingState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Exists, Value, and ValueType.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $key = Get-Item -LiteralPath $Operation.RegistryPath -ErrorAction SilentlyContinue
  $exists = $false
  $value = $null
  $valueType = $null
  if ($key) {
    $exists = $key.GetValueNames() -contains $Operation.ValueName
    if ($exists) {
      $value = $key.GetValue($Operation.ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      $valueType = $key.GetValueKind($Operation.ValueName).ToString()
    }
  }

  [pscustomobject]@{
    Exists = $exists
    Value = $value
    ValueType = $valueType
  }
}

function Set-RideSettingState {
  <#
  .SYNOPSIS
    Apply a declared registry value or remove it.

  .DESCRIPTION
    Creates a missing key, corrects a mismatched value kind, and writes the supplied value. Null
    removes the value. Engine-internal mutation: this function does not capture state or implement
    ShouldProcess.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER Value
    Declared registry data; a null value removes the named value.

  .EXAMPLE
    Get-Help Set-RideSettingState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][AllowNull()] $Value
  )

  if ($null -eq $Value) {
    Remove-ItemProperty -LiteralPath $Operation.RegistryPath -Name $Operation.ValueName -Force -ErrorAction SilentlyContinue
    return
  }

  if (-not (Test-Path -LiteralPath $Operation.RegistryPath)) {
    New-Item -Path $Operation.RegistryPath -Force | Out-Null
  }

  $current = Get-RideSettingState -Operation $Operation
  if ($current.Exists -and $current.ValueType -ne $Operation.ValueType) {
    Remove-ItemProperty -LiteralPath $Operation.RegistryPath -Name $Operation.ValueName -Force
  }

  New-ItemProperty -LiteralPath $Operation.RegistryPath -Name $Operation.ValueName -Value $Value -PropertyType $Operation.ValueType -Force | Out-Null
}

function Restore-RideSettingState {
  <#
  .SYNOPSIS
    Restore a captured registry value and its original kind.

  .DESCRIPTION
    Recreates a previously existing value with its saved type, or removes a value originally absent.
    Removes a newly created key only when empty. Call through Restore-RideRun for
    scope/target/preview checks.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER Snapshot
    Captured pre-change state for this operation, read from the matching saved run.

  .EXAMPLE
    Get-Help Restore-RideSettingState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $Snapshot
  )

  if ($Snapshot.Exists) {
    $restoreOperation = $Operation.Clone()
    $restoreOperation.ValueType = $Snapshot.ValueType
    Set-RideSettingState -Operation $restoreOperation -Value $Snapshot.Value
    return
  }

  Remove-ItemProperty -LiteralPath $Operation.RegistryPath -Name $Operation.ValueName -Force -ErrorAction SilentlyContinue
  if (-not $Snapshot.KeyExisted) {
    $key = Get-Item -LiteralPath $Operation.RegistryPath -ErrorAction SilentlyContinue
    if ($key -and $key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0) {
      Remove-Item -LiteralPath $Operation.RegistryPath -Force -ErrorAction SilentlyContinue
    }
  }
}

Export-ModuleMember -Function Get-RideSettingState, Set-RideSettingState, Restore-RideSettingState
