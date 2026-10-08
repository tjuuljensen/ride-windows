<#
.SYNOPSIS
  Inspect and restore Windows service startup and runtime state.

.DESCRIPTION
  Defines service handlers using Get-Service and Win32_Service. Writes transition
  Automatic/Manual/Disabled startup and stable Running/Stopped/Paused runtime states. Import defines
  commands only.

.EXAMPLE
  Import-Module .\modules\RIDE-Services.psm1
  Import definitions; inspect exported commands with Get-Help before use.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return the types documented in their individual help.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Service/CIM cmdlets and elevation for configuration changes.
  File/environment inputs: Catalog ServiceName and state maps; saved StartupType and Status.
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

function Get-RideWindowsServiceState {
  <#
  .SYNOPSIS
    Read a Windows service startup type and runtime status.

  .DESCRIPTION
    Combines service-manager status and Win32_Service start mode; rejects unsupported startup modes.
    No changes occur.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideWindowsServiceState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. StartupType and Status.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $service = Get-Service -Name $Operation.ServiceName -ErrorAction Stop
  $cimService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($Operation.ServiceName)'" -ErrorAction Stop
  if (-not $cimService) { throw "Windows service '$($Operation.ServiceName)' was not found." }

  [pscustomobject]@{
    StartupType = switch ($cimService.StartMode) {
      'Auto' { 'Automatic' }
      'Manual' { 'Manual' }
      'Disabled' { 'Disabled' }
      default { throw "Unsupported startup mode '$($cimService.StartMode)' for '$($Operation.ServiceName)'." }
    }
    Status = [string]$service.Status
  }
}

function Set-RideWindowsServiceState {
  <#
  .SYNOPSIS
    Apply the catalog service startup and runtime state.

  .DESCRIPTION
    Resolves a declared state, rejects unstable transition states, and changes startup/status as
    needed. Use the engine to preview and capture the prior state.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER State
    Declared desired state for the selected catalog operation.

  .EXAMPLE
    Get-Help Set-RideWindowsServiceState -Full
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
    [Parameter(Mandatory = $true)][string] $State
  )

  if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
  $desired = $Operation.States[$State]
  Set-RideWindowsServiceConfiguration -Operation $Operation -StartupType $desired.StartupType -Status $desired.Status
}

function Restore-RideWindowsServiceState {
  <#
  .SYNOPSIS
    Restore captured service startup and runtime state.

  .DESCRIPTION
    Applies saved StartupType and Status using focused service configuration. Use Restore-RideRun;
    direct calls bypass engine safeguards.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER Snapshot
    Captured pre-change state for this operation, read from the matching saved run.

  .EXAMPLE
    Get-Help Restore-RideWindowsServiceState -Full
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

  Set-RideWindowsServiceConfiguration -Operation $Operation -StartupType $Snapshot.StartupType -Status $Snapshot.Status
}

function Set-RideWindowsServiceConfiguration {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][ValidateSet('Automatic', 'Manual', 'Disabled')][string] $StartupType,
    [Parameter(Mandatory = $true)][ValidateSet('Running', 'Stopped', 'Paused')][string] $Status
  )

  $service = Get-Service -Name $Operation.ServiceName -ErrorAction Stop
  if ($service.Status -notin @('Running', 'Stopped', 'Paused')) {
    throw "Cannot change '$($Operation.ServiceName)' while its status is '$($service.Status)'. Retry after the service reaches a stable state."
  }
  if ([string]$service.StartType -ne $StartupType) {
    Set-Service -Name $Operation.ServiceName -StartupType $StartupType -ErrorAction Stop
  }
  if ($Status -eq 'Running' -and $service.Status -ne 'Running') {
    if ($service.Status -eq 'Paused') {
      Resume-Service -Name $Operation.ServiceName -ErrorAction Stop
    }
    else {
      Start-Service -Name $Operation.ServiceName -ErrorAction Stop
    }
  }
  elseif ($Status -eq 'Stopped' -and $service.Status -ne 'Stopped') {
    Stop-Service -Name $Operation.ServiceName -ErrorAction Stop
  }
  elseif ($Status -eq 'Paused' -and $service.Status -ne 'Paused') {
    if ($service.Status -eq 'Stopped') {
      Start-Service -Name $Operation.ServiceName -ErrorAction Stop
    }
    Suspend-Service -Name $Operation.ServiceName -ErrorAction Stop
  }
}

Export-ModuleMember -Function Get-RideWindowsServiceState, Set-RideWindowsServiceState, Restore-RideWindowsServiceState
