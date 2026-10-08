<#
.SYNOPSIS
  Capture, reset, and restore per-app background registry overrides.

.DESCRIPTION
  Reads only declared value names beneath the selected application root. Reset removes existing
  overrides; Restore recreates captured values and registry types. Import defines commands only.

.EXAMPLE
  Import-Module .\modules\RIDE-BackgroundApps.psm1
  Import definitions; inspect exported commands with Get-Help before use.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return the types documented in their individual help.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Windows registry provider and the RIDE-Settings handler available through the
  engine.
  File/environment inputs: Catalog RegistryPath/ValueNames and the captured Overrides list.
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

function Get-RideBackgroundAppOverrides {
  <#
  .SYNOPSIS
    Capture declared per-application background overrides.

  .DESCRIPTION
    Enumerates the catalog registry root and captures only listed value names with their types.
    Returns presence/count and the captured override array.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideBackgroundAppOverrides -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Present, Count, and Overrides.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $overrides = New-Object System.Collections.Generic.List[object]
  $applications = Get-ChildItem -LiteralPath $Operation.RegistryPath -ErrorAction SilentlyContinue
  foreach ($application in $applications) {
    foreach ($valueName in $Operation.ValueNames) {
      $state = Get-RideSettingState -Operation @{
        RegistryPath = $application.PSPath
        ValueName = $valueName
      }
      if ($state.Exists) {
        $overrides.Add([pscustomobject]@{
          SubKey = $application.PSChildName
          ValueName = $valueName
          Value = $state.Value
          ValueType = $state.ValueType
        })
      }
    }
  }

  [pscustomobject]@{
    Present = ($overrides.Count -gt 0)
    Count = $overrides.Count
    Overrides = $overrides.ToArray()
  }
}

function Reset-RideBackgroundAppOverrides {
  <#
  .SYNOPSIS
    Remove the declared per-app override values.

  .DESCRIPTION
    Deletes only existing named values beneath the selected app root. Does not remove the app keys.
    Invoke through the engine after snapshot capture.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Reset-RideBackgroundAppOverrides -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  foreach ($application in (Get-ChildItem -LiteralPath $Operation.RegistryPath -ErrorAction SilentlyContinue)) {
    foreach ($valueName in $Operation.ValueNames) {
      $state = Get-RideSettingState -Operation @{ RegistryPath = $application.PSPath; ValueName = $valueName }
      if ($state.Exists) {
        Remove-ItemProperty -LiteralPath $application.PSPath -Name $valueName -Force -ErrorAction Stop
      }
    }
  }
}

function Restore-RideBackgroundAppOverrides {
  <#
  .SYNOPSIS
    Recreate captured per-app override values.

  .DESCRIPTION
    Recreates missing subkeys and restores captured value names, data, and registry kinds. Does not
    clear unrelated values; use the saved run through the engine.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER Snapshot
    Captured pre-change state for this operation, read from the matching saved run.

  .EXAMPLE
    Get-Help Restore-RideBackgroundAppOverrides -Full
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

  foreach ($override in $Snapshot.Overrides) {
    $path = Join-Path $Operation.RegistryPath $override.SubKey
    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -LiteralPath $path -Name $override.ValueName -Value $override.Value -PropertyType $override.ValueType -Force | Out-Null
  }
}

Export-ModuleMember -Function Get-RideBackgroundAppOverrides, Reset-RideBackgroundAppOverrides, Restore-RideBackgroundAppOverrides
