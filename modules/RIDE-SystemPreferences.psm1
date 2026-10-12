<#
.SYNOPSIS
  Manage focused Defender and SMB preferences through their documented cmdlets.
.DESCRIPTION
  Reads and writes one declared preference; import has no system side effects.
  Does not add exclusions, change firewall rules, install features or send files.
  The engine owns preview, snapshots and partial-failure reporting.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Defender/SmbShare/CimCmdlets modules and elevation for writes.
  Recovery: Restore the captured literal preference; policy/tamper protection may reject writes.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add controlled-folder-access and SMB protocol preferences.
#>
function Get-RideDefenderPreferenceState {
  <#
  .SYNOPSIS
    Inspect Controlled Folder Access without changing protection.
  .PARAMETER Operation
    Catalog DefenderPreference operation.
  .OUTPUTS
    PSCustomObject with literal preference value.
  #>
  param([hashtable] $Operation)
  [pscustomobject]@{ Value = [int](Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess }
}
function Set-RideDefenderPreferenceState {
  <#
  .SYNOPSIS
    Set Controlled Folder Access and propagate policy/tamper failures.
  .PARAMETER Operation
    Catalog operation.
  .PARAMETER Value
    Literal supported mode; restore retains captured modes beyond catalog choices.
  .OUTPUTS
    None.
  #>
  param([hashtable] $Operation, [ValidateRange(0, 6)][int] $Value)
  if ((Get-RideDefenderPreferenceState $Operation).Value -eq $Value) { return }
  Set-MpPreference -EnableControlledFolderAccess $Value -ErrorAction Stop
}
function Get-RideSmbProtocolState {
  <#
  .SYNOPSIS
    Inspect the declared SMB server protocol flag.
  .PARAMETER Operation
    Catalog preference: EnableSMB1Protocol or EnableSMB2Protocol.
  .OUTPUTS
    PSCustomObject with driver availability and literal Boolean flag.
  #>
  param([hashtable] $Operation)
  if ($Operation.Preference -notin @('EnableSMB1Protocol', 'EnableSMB2Protocol')) { throw 'Unsupported SMB preference.' }
  $driverName = if ($Operation.Preference -eq 'EnableSMB1Protocol') { 'srv' } else { 'srv2' }
  $drivers = @(Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='$driverName'" -ErrorAction Stop)
  if ($drivers.Count -eq 0) { return [pscustomobject]@{ Available = $false; Value = $null } }
  if ($drivers.Count -ne 1) { throw 'Expected exactly one SMB protocol driver.' }
  [pscustomobject]@{ Available = $true; Value = [bool](Get-SmbServerConfiguration -ErrorAction Stop).($Operation.Preference) }
}
function Set-RideSmbProtocolState {
  <#
  .SYNOPSIS
    Change a declared SMB flag without installing client/server components.
  .PARAMETER Operation
    Catalog preference allowlist.
  .PARAMETER Value
    Desired Boolean flag.
  .OUTPUTS
    None; unexpected metadata and system errors throw.
  #>
  param([hashtable] $Operation, [bool] $Value)
  if ($Operation.Preference -notin @('EnableSMB1Protocol', 'EnableSMB2Protocol')) { throw 'Unsupported SMB preference.' }
  $current = Get-RideSmbProtocolState $Operation
  if (-not $current.Available) { throw 'SMB server protocol driver is unavailable; component installation is a separate operation.' }
  if ($current.Value -eq $Value) { return }
  $parameters = @{ Force = $true; ErrorAction = 'Stop' }
  $parameters[$Operation.Preference] = $Value
  Set-SmbServerConfiguration @parameters | Out-Null
}
Export-ModuleMember -Function Get-RideDefenderPreferenceState, Set-RideDefenderPreferenceState, Get-RideSmbProtocolState, Set-RideSmbProtocolState
