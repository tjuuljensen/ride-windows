function Get-RideBackgroundAppOverrides {
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
