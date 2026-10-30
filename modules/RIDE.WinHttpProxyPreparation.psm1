<#
.SYNOPSIS
  Prepare explicit, single-scope WinHTTP proxy configuration and recovery values.
.DESCRIPTION
  Builds a complete JSON settings document for the documented netsh WinHTTP
  advanced proxy command from a captured observation and explicit field edits.
  Recovery preparation checks that the observed configuration still matches the
  prepared configuration. This module performs no query, file write or mutation.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Inputs: Version-1 WinHTTP proxy observation from RIDE.WinHttpProxyInventory.
  Recovery: Prepared values only; exact underlying literal state is not proven.
  Version: 0.1.0.
  Changelog: 0.1.0: Add scoped WinHTTP configuration and conflict-aware recovery preparation.
.LINK
  ../docs/user-proxy-inventory.md
.LINK
  https://learn.microsoft.com/en-us/windows/win32/winhttp/netsh-exe-commands
#>
$ErrorActionPreference='Stop'

function Assert-RideWinHttpProxyPreparationFields {
  param($Value,[string[]]$Names)
  if($null -eq $Value){throw 'Missing WinHTTP proxy preparation record.'}
  foreach($name in $Names){
    $present=if($Value -is [Collections.IDictionary]){$Value.Contains($name)}else{$null -ne $Value.PSObject.Properties[$name]}
    if(-not $present){throw "Missing WinHTTP proxy preparation field: $name."}
  }
}

function Assert-RideWinHttpProxyPreparationString {
  param($Value,[string]$Name)
  if($Value -isnot [string] -or $Value.Length -gt 32768 -or $Value.Contains([string][char]0)){throw "WinHTTP proxy field '$Name' must be a string of at most 32768 characters without NUL."}
}

function ConvertTo-RideWinHttpProxyPreparationObservation {
  param($Observation)
  Assert-RideWinHttpProxyPreparationFields $Observation @('SchemaVersion','Kind','Status','Scope','ProxyIsEnabled','Proxy','ProxyReported','ProxyBypass','ProxyBypassReported','AutoConfigIsEnabled','AutoconfigUrl','AutoconfigUrlReported','AutoDetect','PerUserProxySettings')
  if($Observation.SchemaVersion -ne 1 -or $Observation.Kind -cne 'WinHttpProxyConfiguration' -or $Observation.Status -cne 'Captured' -or $Observation.Scope -cnotin @('User','Machine') -or $Observation.ProxyIsEnabled -isnot [bool] -or $Observation.ProxyReported -isnot [bool] -or $Observation.ProxyBypassReported -isnot [bool] -or $Observation.AutoConfigIsEnabled -isnot [bool] -or $Observation.AutoconfigUrlReported -isnot [bool] -or $Observation.AutoDetect -isnot [bool] -or $Observation.PerUserProxySettings -isnot [bool]){throw 'Invalid WinHTTP proxy observation schema.'}
  if(($Observation.Scope -ceq 'User') -ne $Observation.PerUserProxySettings){throw 'WinHTTP observation scope disagrees with PerUserProxySettings.'}
  foreach($field in @(@('Proxy',$Observation.Proxy,$Observation.ProxyReported),@('ProxyBypass',$Observation.ProxyBypass,$Observation.ProxyBypassReported),@('AutoconfigUrl',$Observation.AutoconfigUrl,$Observation.AutoconfigUrlReported))){
    if($field[2]){Assert-RideWinHttpProxyPreparationString $field[1] $field[0]}
    elseif($null -ne $field[1]){throw "WinHTTP omitted field '$($field[0])' unexpectedly contains a value."}
  }
  if($Observation.ProxyIsEnabled -and (-not $Observation.ProxyReported -or [string]::IsNullOrWhiteSpace($Observation.Proxy))){throw 'WinHTTP observation reports an enabled proxy without its string value.'}
  if($Observation.AutoConfigIsEnabled -and (-not $Observation.AutoconfigUrlReported -or [string]::IsNullOrWhiteSpace($Observation.AutoconfigUrl))){throw 'WinHTTP observation reports enabled auto-configuration without its URL.'}
  [pscustomobject]@{
    Scope=$Observation.Scope
    Proxy=$(if($Observation.ProxyReported){$Observation.Proxy}else{''})
    ProxyBypass=$(if($Observation.ProxyBypassReported){$Observation.ProxyBypass}else{''})
    AutoconfigUrl=$(if($Observation.AutoconfigUrlReported){$Observation.AutoconfigUrl}else{''})
    AutoDetect=[bool]$Observation.AutoDetect
    ReportedFields=[pscustomobject]@{Proxy=[bool]$Observation.ProxyReported;ProxyBypass=[bool]$Observation.ProxyBypassReported;AutoconfigUrl=[bool]$Observation.AutoconfigUrlReported}
  }
}

function Assert-RideWinHttpProxyCompleteStringObservation {
  param($Normalized)
  foreach($name in @('Proxy','ProxyBypass','AutoconfigUrl')){
    if(-not $Normalized.ReportedFields.$name){throw "WinHTTP omitted '$name'; refusing a complete settings payload because its prior value is unknown."}
  }
}

function ConvertTo-RideWinHttpProxySettingsJson {
  param($Values)
  $ordered=[ordered]@{Proxy=[string]$Values.Proxy;ProxyBypass=[string]$Values.ProxyBypass;AutoconfigUrl=[string]$Values.AutoconfigUrl;AutoDetect=[bool]$Values.AutoDetect}
  ConvertTo-Json -InputObject $ordered -Depth 3 -Compress
}

function New-RideWinHttpProxyConfigurationPatch {
  <#
  .SYNOPSIS
    Prepare a complete advanced WinHTTP settings document for one explicit scope.
  .DESCRIPTION
    Copies unselected fields from a captured command observation and applies only
    explicitly bound Proxy, ProxyBypass, AutoconfigUrl and AutoDetect inputs.
    It refuses an observation for a different User/Machine scope.
  .PARAMETER Observation
    Version-1 record from Get-RideWinHttpProxyObservation or its parser.
  .PARAMETER Scope
    Explicit `User` or `Machine` scope. Machine writes require elevation at apply time.
  .EXAMPLE
    New-RideWinHttpProxyConfigurationPatch -Observation $state -Scope User -AutoDetect:$false
  .OUTPUTS
    PSCustomObject containing desired values, JSON settings, and a preparation snapshot.
  .NOTES
    Preparation refuses observations where `show advproxy` omits any string
    field because the full settings document would otherwise replace an unknown
    prior value with empty. It still does not authorize mutation or claim exact
    underlying registry recovery.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Observation,
    [Parameter(Mandatory)][ValidateSet('User','Machine')][string]$Scope,
    [Parameter()][AllowEmptyString()][string]$Proxy,
    [Parameter()][AllowEmptyString()][string]$ProxyBypass,
    [Parameter()][AllowEmptyString()][string]$AutoconfigUrl,
    [Parameter()][bool]$AutoDetect
  )
  $original=ConvertTo-RideWinHttpProxyPreparationObservation $Observation
  if($original.Scope -cne $Scope){throw 'Requested WinHTTP scope differs from the captured scope.'}
  Assert-RideWinHttpProxyCompleteStringObservation $original
  $desired=[pscustomobject]@{Scope=$Scope;Proxy=$original.Proxy;ProxyBypass=$original.ProxyBypass;AutoconfigUrl=$original.AutoconfigUrl;AutoDetect=$original.AutoDetect}
  foreach($name in @('Proxy','ProxyBypass','AutoconfigUrl')){if($PSBoundParameters.ContainsKey($name)){Assert-RideWinHttpProxyPreparationString $PSBoundParameters[$name] $name;$desired.$name=$PSBoundParameters[$name]}}
  if($PSBoundParameters.ContainsKey('AutoDetect')){$desired.AutoDetect=[bool]$AutoDetect}
  $changed=@()
  foreach($name in @('Proxy','ProxyBypass','AutoconfigUrl')){if(-not [string]::Equals([string]$desired.$name,[string]$original.$name,[StringComparison]::Ordinal)){$changed+=$name}}
  if($desired.AutoDetect -ne $original.AutoDetect){$changed+='AutoDetect'}
  $json=ConvertTo-RideWinHttpProxySettingsJson $desired
  $snapshot=[pscustomobject]@{
    SchemaVersion=1;Kind='WinHttpProxyPreparationSnapshot';Scope=$Scope
    OriginalValues=[pscustomobject]@{Scope=$Scope;Proxy=$original.Proxy;ProxyBypass=$original.ProxyBypass;AutoconfigUrl=$original.AutoconfigUrl;AutoDetect=$original.AutoDetect}
    OriginalReportedFields=$original.ReportedFields
    ExpectedValues=[pscustomobject]@{Proxy=$desired.Proxy;ProxyBypass=$desired.ProxyBypass;AutoconfigUrl=$desired.AutoconfigUrl;AutoDetect=$desired.AutoDetect}
    ChangedFields=@($changed)
  }
  [pscustomobject]@{
    SchemaVersion=1;Kind='WinHttpProxyPreparation';Scope=$Scope
    ChangeRequired=($changed.Count -gt 0);ChangedFields=@($changed)
    DesiredValues=$desired;SettingsJson=$json;Snapshot=$snapshot
    RequiresElevation=($Scope -ceq 'Machine');ReadyForMutation=$false;MutationAuthorized=$false
    ExactLiteralStateVerified=$false;RecoveryPrecision='ReportedConfiguration'
    Limitation='In-memory preparation only; underlying registry state is not verified.'
  }
}

function Restore-RideWinHttpProxyConfigurationPatch {
  <#
  .SYNOPSIS
    Prepare conflict-aware recovery of a WinHTTP configuration patch.
  .PARAMETER Observation
    Fresh supplied observation for the same scope.
  .PARAMETER Snapshot
    Snapshot from New-RideWinHttpProxyConfigurationPatch.
  .EXAMPLE
    Restore-RideWinHttpProxyConfigurationPatch -Observation $current -Snapshot $patch.Snapshot
  .OUTPUTS
    PSCustomObject containing prepared original values and command JSON.
  .NOTES
    This is not a live comparison or setter. It refuses incomplete observations
    and snapshots; hidden/omitted literal values cannot be recovered exactly.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Observation,[Parameter(Mandatory)]$Snapshot)
  $current=ConvertTo-RideWinHttpProxyPreparationObservation $Observation
  Assert-RideWinHttpProxyCompleteStringObservation $current
  Assert-RideWinHttpProxyPreparationFields $Snapshot @('SchemaVersion','Kind','Scope','OriginalValues','OriginalReportedFields','ExpectedValues','ChangedFields')
  if($Snapshot.SchemaVersion -ne 1 -or $Snapshot.Kind -cne 'WinHttpProxyPreparationSnapshot' -or $Snapshot.Scope -cne $current.Scope){throw 'WinHTTP proxy snapshot does not match its schema or scope.'}
  foreach($name in @('Proxy','ProxyBypass','AutoconfigUrl')){
    Assert-RideWinHttpProxyPreparationFields $Snapshot.OriginalValues @($name)
    Assert-RideWinHttpProxyPreparationFields $Snapshot.ExpectedValues @($name)
    Assert-RideWinHttpProxyPreparationString $Snapshot.OriginalValues.$name $name
    Assert-RideWinHttpProxyPreparationString $Snapshot.ExpectedValues.$name $name
  }
  Assert-RideWinHttpProxyPreparationFields $Snapshot.OriginalReportedFields @('Proxy','ProxyBypass','AutoconfigUrl')
  foreach($name in @('Proxy','ProxyBypass','AutoconfigUrl')){
    if($Snapshot.OriginalReportedFields.$name -isnot [bool]){throw "WinHTTP snapshot reported-field marker '$name' must be Boolean."}
    if(-not $Snapshot.OriginalReportedFields.$name){throw "WinHTTP snapshot omitted '$name'; exact prior value is unavailable."}
  }
  Assert-RideWinHttpProxyPreparationFields $Snapshot.OriginalValues @('AutoDetect')
  Assert-RideWinHttpProxyPreparationFields $Snapshot.ExpectedValues @('AutoDetect')
  if($Snapshot.OriginalValues.AutoDetect -isnot [bool] -or $Snapshot.ExpectedValues.AutoDetect -isnot [bool]){throw 'WinHTTP snapshot AutoDetect values must be Boolean.'}
  $computedChanged=@()
  foreach($name in @('Proxy','ProxyBypass','AutoconfigUrl')){if(-not [string]::Equals([string]$Snapshot.OriginalValues.$name,[string]$Snapshot.ExpectedValues.$name,[StringComparison]::Ordinal)){$computedChanged+=$name}}
  if($Snapshot.OriginalValues.AutoDetect -ne $Snapshot.ExpectedValues.AutoDetect){$computedChanged+='AutoDetect'}
  $storedChanged=@($Snapshot.ChangedFields)
  if($storedChanged.Count -ne $computedChanged.Count){throw 'WinHTTP proxy snapshot changed-field list disagrees with its reconstructed edit.'}
  for($i=0;$i -lt $storedChanged.Count;$i++){if($storedChanged[$i] -isnot [string] -or $storedChanged[$i] -cne $computedChanged[$i]){throw 'WinHTTP proxy snapshot changed-field list disagrees with its reconstructed edit.'}}
  $values=[pscustomobject]@{Scope=$current.Scope;Proxy=$current.Proxy;ProxyBypass=$current.ProxyBypass;AutoconfigUrl=$current.AutoconfigUrl;AutoDetect=$current.AutoDetect}
  foreach($name in @('Proxy','ProxyBypass','AutoconfigUrl')){if(-not [string]::Equals([string]$values.$name,[string]$Snapshot.ExpectedValues.$name,[StringComparison]::Ordinal)){throw "WinHTTP field '$name' changed after preparation; refusing recovery."}}
  if($values.AutoDetect -ne $Snapshot.ExpectedValues.AutoDetect){throw 'WinHTTP field AutoDetect changed after preparation; refusing recovery.'}
  $original=[pscustomobject]@{Scope=$Snapshot.Scope;Proxy=$Snapshot.OriginalValues.Proxy;ProxyBypass=$Snapshot.OriginalValues.ProxyBypass;AutoconfigUrl=$Snapshot.OriginalValues.AutoconfigUrl;AutoDetect=$Snapshot.OriginalValues.AutoDetect}
  $json=ConvertTo-RideWinHttpProxySettingsJson $original
  [pscustomobject]@{SchemaVersion=1;Kind='WinHttpProxyRecoveryPreparation';Scope=$Snapshot.Scope;ChangeRequired=(@($Snapshot.ChangedFields).Count -gt 0);DesiredValues=$original;SettingsJson=$json;ReadyForMutation=$false;MutationAuthorized=$false;ExactLiteralStateVerified=$false;RecoveryPrecision='ReportedConfiguration';Limitation='Supplied-data recovery only; live compare, native setter, durable state and exact literal restoration are not implemented.'}
}

Export-ModuleMember -Function New-RideWinHttpProxyConfigurationPatch,Restore-RideWinHttpProxyConfigurationPatch
