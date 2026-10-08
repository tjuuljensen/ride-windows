function Get-RideWindowsServiceState {
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
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $State
  )

  if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
  $desired = $Operation.States[$State]
  Set-RideWindowsServiceConfiguration -Operation $Operation -StartupType $desired.StartupType -Status $desired.Status
}

function Restore-RideWindowsServiceState {
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
