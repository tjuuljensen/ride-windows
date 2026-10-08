function Get-RideBootConfigurationState {
  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $output = (& bcdedit.exe /enum '{current}' /v 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { throw "BCDEdit query failed for '$($Operation.BcdElement)': $($output.Trim())" }
  $pattern = '(?im)^\s*{0}\s+(.+?)\s*$' -f [regex]::Escape($Operation.BcdElement)
  $match = [regex]::Match($output, $pattern)
  [pscustomobject]@{
    Exists = $match.Success
    Value = if ($match.Success) { $match.Groups[1].Value.Trim() } else { $null }
  }
}

function Set-RideBootConfigurationState {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $State
  )

  if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
  $value = $Operation.States[$State]
  if ($null -eq $value) {
    Invoke-RideBootConfigurationCommand -Arguments @('/deletevalue', '{current}', $Operation.BcdElement)
  }
  else {
    Invoke-RideBootConfigurationCommand -Arguments @('/set', '{current}', $Operation.BcdElement, [string]$value)
  }
}

function Restore-RideBootConfigurationState {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $Snapshot
  )

  if ($Snapshot.Exists) {
    Invoke-RideBootConfigurationCommand -Arguments @('/set', '{current}', $Operation.BcdElement, [string]$Snapshot.Value)
  }
  else {
    Invoke-RideBootConfigurationCommand -Arguments @('/deletevalue', '{current}', $Operation.BcdElement)
  }
}

function Invoke-RideBootConfigurationCommand {
  param([Parameter(Mandatory = $true)][string[]] $Arguments)

  $output = (& bcdedit.exe @Arguments 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { throw "BCDEdit command failed: $($output.Trim())" }
}

Export-ModuleMember -Function Get-RideBootConfigurationState, Set-RideBootConfigurationState, Restore-RideBootConfigurationState
