function Get-RideSettingState {
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
