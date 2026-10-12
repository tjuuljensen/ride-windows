<#
.SYNOPSIS
  Inspect and restore enablement of one declared existing Windows task.
.DESCRIPTION
  Never creates, deletes, starts or stops tasks. Missing tasks are unavailable.
  The engine owns preview, snapshots and partial-failure reporting.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: ScheduledTasks module; administrator rights for machine tasks.
  Recovery: Restore the captured enablement flag; task definitions and history remain independent.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add bounded existing-task enablement lifecycle.
#>
function Get-RideScheduledTaskState {
  <#
  .SYNOPSIS
    Read the declared task without running it.
  .PARAMETER Operation
    Catalog task path and name.
  .OUTPUTS
    PSCustomObject with availability, task identity and enablement.
  #>
  param([hashtable] $Operation)
  if ($Operation.TaskPath -notmatch '^\\Microsoft\\(Windows\\[^*?\r\n]+|Office)\\$' -or -not $Operation.TaskName -or $Operation.TaskName -match '[\\*?\r\n]') { throw 'Invalid exact task identity.' }
  try { $task = Get-ScheduledTask -TaskPath $Operation.TaskPath -TaskName $Operation.TaskName -ErrorAction Stop }
  catch {
    if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }
    return [pscustomobject]@{ Available = $false; TaskPath = $Operation.TaskPath; TaskName = $Operation.TaskName; Enabled = $null }
  }
  if (@($task).Count -eq 0) { return [pscustomobject]@{ Available = $false; TaskPath = $Operation.TaskPath; TaskName = $Operation.TaskName; Enabled = $null } }
  if (@($task).Count -ne 1 -or $task.TaskPath -ne $Operation.TaskPath -or $task.TaskName -ne $Operation.TaskName) { throw 'Expected exactly one declared scheduled task.' }
  [pscustomobject]@{ Available = $true; TaskPath = $task.TaskPath; TaskName = $task.TaskName; Enabled = [bool]$task.Settings.Enabled }
}
function Set-RideScheduledTaskEnabled {
  <#
  .SYNOPSIS
    Change only the declared task's enablement.
  .PARAMETER Operation
    Catalog task identity.
  .PARAMETER Enabled
    Desired enablement flag.
  .OUTPUTS
    None; missing tasks or system failures throw.
  #>
  param([hashtable] $Operation, [bool] $Enabled)
  $current = Get-RideScheduledTaskState $Operation
  if (-not $current.Available) { throw "Task is unavailable: $($Operation.TaskPath)$($Operation.TaskName)" }
  if ($current.Enabled -eq $Enabled) { return }
  if ($Enabled) { Enable-ScheduledTask -TaskPath $Operation.TaskPath -TaskName $Operation.TaskName -ErrorAction Stop | Out-Null }
  else { Disable-ScheduledTask -TaskPath $Operation.TaskPath -TaskName $Operation.TaskName -ErrorAction Stop | Out-Null }
}
function Restore-RideScheduledTaskState {
  <#
  .SYNOPSIS
    Restore captured enablement without replacing the task definition.
  .PARAMETER Operation
    Catalog task identity; snapshot paths cannot redirect writes.
  .PARAMETER Snapshot
    Captured availability, identity and Boolean enablement.
  .OUTPUTS
    None; invalid or unavailable snapshots throw before writes.
  #>
  param([hashtable] $Operation, $Snapshot)
  if (-not $Snapshot.Available -or $Snapshot.Enabled -isnot [bool] -or $Snapshot.TaskPath -ne $Operation.TaskPath -or $Snapshot.TaskName -ne $Operation.TaskName) { throw 'Invalid scheduled-task snapshot.' }
  Set-RideScheduledTaskEnabled $Operation $Snapshot.Enabled
}
Export-ModuleMember -Function Get-RideScheduledTaskState, Set-RideScheduledTaskEnabled, Restore-RideScheduledTaskState
