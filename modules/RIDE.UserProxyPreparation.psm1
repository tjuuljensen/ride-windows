<#
.SYNOPSIS
  Prepare narrowly owned user proxy flag/URL edits and recovery in memory.
.DESCRIPTION
  Accepts supplied default/LAN observations. Detection and setup-script choices
  preserve manual proxy, bypass, direct and unknown flags. Recovery refuses drift
  in changed fields and preserves unrelated current edits. No native query/setter,
  PAC retrieval, file writer or engine state-store integration is included.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7. Native acceptance pending.
  Prerequisites: Schema-1 captured FlagsUi observation of an explicit user/session.
  File/environment inputs: Supplied objects only; import/completion perform no I/O.
  Recovery: Returned values are preparation, never authorization for live mutation.
  Version: 0.1.0.
  Changelog: 0.1.0: Add owned detection/PAC preparation and conflict-aware recovery.
.LINK
  ../docs/user-proxy-inventory.md
#>
$ErrorActionPreference='Stop'

function Assert-RideProxyPreparationFields {
  param($Value,[string[]]$Names)
  if($null -eq $Value){throw 'Missing proxy preparation record.'}
  foreach($name in $Names){
    $present=if($Value -is [Collections.IDictionary]){$Value.Contains($name)}else{$null -ne $Value.PSObject.Properties[$name]}
    if(-not $present){throw ('Missing proxy preparation field: '+$name)}
  }
}

function ConvertTo-RideProxyPreparationNumber {
  param($Value)
  if($null -eq $Value -or $Value -is [bool] -or $Value -is [string] -or $Value -isnot [ValueType] -or $Value -lt 0 -or $Value -gt [uint32]::MaxValue -or [decimal]$Value -ne [decimal][uint32]$Value){throw 'Invalid unsigned proxy flags.'}
  [uint32]$Value
}

function Assert-RideProxyPreparationText {
  param($Value)
  if($null -ne $Value -and ($Value -isnot [string] -or $Value.Length -gt 32768 -or $Value.Contains([string][char]0))){throw 'Invalid proxy preparation string.'}
}

function ConvertTo-RideProxyPreparationObservation {
  param($Observation)
  Assert-RideProxyPreparationFields $Observation @('SchemaVersion','Kind','Status','FlagsSource','UiQueryError','ComputerName','UserSid','SessionId','ConnectionKind','ConnectionName','Flags','ProxyServer','ProxyBypass','AutoConfigUrl')
  if($null -eq $Observation -or $Observation.SchemaVersion -ne 1 -or $Observation.Kind -cne 'UserProxyObservation' -or $Observation.Status -cne 'Captured' -or $Observation.FlagsSource -cne 'FlagsUi' -or $null -ne $Observation.UiQueryError -or $Observation.ConnectionKind -cne 'DefaultLan' -or $null -ne $Observation.ConnectionName){throw 'Proxy preparation requires a captured schema-1 default/LAN FlagsUi observation.'}
  if($Observation.ComputerName -isnot [string] -or [string]::IsNullOrWhiteSpace($Observation.ComputerName) -or $Observation.ComputerName.Length -gt 255 -or $Observation.ComputerName -match '[\x00-\x1f]' -or $Observation.UserSid -isnot [string] -or $Observation.UserSid -cnotmatch '^S-1-[0-9]+(?:-[0-9]+)+$'){throw 'Invalid proxy preparation identity.'}
  $session=ConvertTo-RideProxyPreparationNumber $Observation.SessionId
  if($session -lt 1 -or $session -gt [int]::MaxValue){throw 'Invalid proxy preparation session.'}
  $flags=ConvertTo-RideProxyPreparationNumber $Observation.Flags
  foreach($name in @('ProxyServer','ProxyBypass','AutoConfigUrl')){Assert-RideProxyPreparationText $Observation.$name}
  [pscustomobject]@{
    SchemaVersion=1;Kind='UserProxyObservation';Status='Captured'
    ComputerName=$Observation.ComputerName;UserSid=$Observation.UserSid;SessionId=[int]$session
    ConnectionKind='DefaultLan';ConnectionName=$null;FlagsSource='FlagsUi';UiQueryError=$null
    Flags=$flags;ProxyServer=$Observation.ProxyServer;ProxyBypass=$Observation.ProxyBypass;AutoConfigUrl=$Observation.AutoConfigUrl
  }
}

function Assert-RideProxyPreparationUrl {
  param($Value)
  Assert-RideProxyPreparationText $Value
  $uri=$null
  if([string]::IsNullOrWhiteSpace($Value) -or $Value -cne $Value.Trim() -or $Value -match '[\x00-\x20\x7f]' -or -not [Uri]::TryCreate($Value,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -notin @('http','https') -or [string]::IsNullOrWhiteSpace($uri.Host) -or $uri.UserInfo){throw 'Setup-script enablement requires a nonempty absolute HTTP/HTTPS URL without whitespace or embedded credentials.'}
  # Validate only: retain the caller's exact spelling, not Uri.AbsoluteUri.
}

function New-RideUserProxyConfigurationPatch {
  <#
  .SYNOPSIS
    Prepare detection/PAC edits without changing live configuration.
  .PARAMETER Observation
    Captured schema-1 default/LAN FlagsUi record, including machine, SID and session.
  .PARAMETER AutomaticDetection
    Unchanged, Enabled or Disabled. Only a changed detection bit becomes owned.
  .PARAMETER SetupScript
    Unchanged, Enabled or Disabled. Disabled retains the existing address.
  .PARAMETER ScriptUrl
    Optional exact HTTP/HTTPS address when SetupScript is Enabled. Omission reuses
    a valid retained URL. This validates syntax without retrieving or executing it.
  .EXAMPLE
    New-RideUserProxyConfigurationPatch -Observation $saved -AutomaticDetection Disabled
  .EXAMPLE
    New-RideUserProxyConfigurationPatch -Observation $saved -SetupScript Enabled -ScriptUrl 'https://proxy.example/config.pac'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Desired literal values and version-1 preparation snapshot.
  .NOTES
    ReadyForMutation remains false. Future integration needs fresh scope/policy
    checks, durable state, ShouldProcess, refresh and native/consumer acceptance.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Observation,
    [ValidateSet('Unchanged','Enabled','Disabled')][string]$AutomaticDetection='Unchanged',
    [ValidateSet('Unchanged','Enabled','Disabled')][string]$SetupScript='Unchanged',
    [AllowNull()][AllowEmptyString()][string]$ScriptUrl
  )
  $original=ConvertTo-RideProxyPreparationObservation $Observation
  $choices=@{Unchanged='Unchanged';Enabled='Enabled';Disabled='Disabled'}
  $AutomaticDetection=$choices[$AutomaticDetection];$SetupScript=$choices[$SetupScript]
  $hasUrl=$PSBoundParameters.ContainsKey('ScriptUrl')
  if($hasUrl -and $SetupScript -ne 'Enabled'){throw 'ScriptUrl is accepted only with SetupScript Enabled; disabling preserves the address.'}
  [uint32]$flags=$original.Flags
  if($AutomaticDetection -eq 'Enabled'){$flags=$flags -bor [uint32]8}
  elseif($AutomaticDetection -eq 'Disabled'){$flags=$flags -band [uint32]4294967287}
  $url=$original.AutoConfigUrl
  if($SetupScript -eq 'Enabled'){
    if($hasUrl){$url=$ScriptUrl}
    Assert-RideProxyPreparationUrl $url
    $flags=$flags -bor [uint32]4
  }elseif($SetupScript -eq 'Disabled'){$flags=$flags -band [uint32]4294967291}
  [uint32]$ownedMask=$original.Flags -bxor $flags
  $ownsUrl=-not [string]::Equals($original.AutoConfigUrl,$url,[StringComparison]::Ordinal)
  $desired=[pscustomobject]@{Flags=$flags;ProxyServer=$original.ProxyServer;ProxyBypass=$original.ProxyBypass;AutoConfigUrl=$url}
  [pscustomobject]@{
    SchemaVersion=1;Kind='UserProxyPreparation';ChangeRequired=($ownedMask -ne 0 -or $ownsUrl)
    DesiredValues=$desired
    Snapshot=[pscustomobject]@{
      SchemaVersion=1;Kind='UserProxyPreparationSnapshot';Original=$original
      AutomaticDetection=$AutomaticDetection;SetupScript=$SetupScript
      HasScriptUrl=$hasUrl;ScriptUrl=$(if($hasUrl){$ScriptUrl}else{$null})
      OwnedFlagMask=$ownedMask;OwnsUrl=$ownsUrl;ExpectedFlags=$flags;ExpectedUrl=$url
    }
    ReadyForMutation=$false;MutationAuthorized=$false;PolicyStatus='NotInspected';EffectiveRoutingVerified=$false
    Limitation='In-memory preparation only; no trusted identity, state persistence, live compare/set, refresh or consumer proof'
  }
}

function Restore-RideUserProxyConfigurationPatch {
  <#
  .SYNOPSIS
    Prepare recovery of changed proxy bits/URL while preserving unrelated edits.
  .PARAMETER Observation
    Current supplied default/LAN FlagsUi observation for the same machine/SID/session.
  .PARAMETER Snapshot
    Version-1 preparation snapshot returned by New-RideUserProxyConfigurationPatch.
  .EXAMPLE
    Restore-RideUserProxyConfigurationPatch -Observation $current -Snapshot $patch.Snapshot
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Recovery values; no native or filesystem action occurs.
  .NOTES
    Conflicting changed bits/URL refuse recovery. Unchanged requested fields are
    unowned. Same-session binding is deliberately narrow; this is not engine restore.
    Schema consistency is not authentication of a snapshot supplied by an operator.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Observation,[Parameter(Mandatory)]$Snapshot)
  $current=ConvertTo-RideProxyPreparationObservation $Observation
  Assert-RideProxyPreparationFields $Snapshot @('SchemaVersion','Kind','Original','AutomaticDetection','SetupScript','HasScriptUrl','ScriptUrl','OwnedFlagMask','OwnsUrl','ExpectedFlags','ExpectedUrl')
  if($null -eq $Snapshot -or $Snapshot.SchemaVersion -ne 1 -or $Snapshot.Kind -cne 'UserProxyPreparationSnapshot' -or $Snapshot.HasScriptUrl -isnot [bool] -or $Snapshot.OwnsUrl -isnot [bool] -or $Snapshot.AutomaticDetection -cnotin @('Unchanged','Enabled','Disabled') -or $Snapshot.SetupScript -cnotin @('Unchanged','Enabled','Disabled')){throw 'Invalid proxy preparation snapshot schema.'}
  $arguments=@{Observation=$Snapshot.Original;AutomaticDetection=$Snapshot.AutomaticDetection;SetupScript=$Snapshot.SetupScript}
  if($Snapshot.HasScriptUrl){$arguments.ScriptUrl=$Snapshot.ScriptUrl}
  elseif($null -ne $Snapshot.ScriptUrl){throw 'Unexpected unowned URL input in proxy snapshot.'}
  $expected=(New-RideUserProxyConfigurationPatch @arguments).Snapshot
  $original=$expected.Original
  [uint32]$mask=ConvertTo-RideProxyPreparationNumber $Snapshot.OwnedFlagMask
  [uint32]$expectedFlags=ConvertTo-RideProxyPreparationNumber $Snapshot.ExpectedFlags
  Assert-RideProxyPreparationText $Snapshot.ExpectedUrl
  if($mask -ne $expected.OwnedFlagMask -or $Snapshot.OwnsUrl -ne $expected.OwnsUrl -or $expectedFlags -ne $expected.ExpectedFlags -or -not [string]::Equals($Snapshot.ExpectedUrl,$expected.ExpectedUrl,[StringComparison]::Ordinal)){throw 'Proxy preparation snapshot disagrees with its reconstructed edit.'}
  if($current.ComputerName -ine $original.ComputerName -or $current.UserSid -cne $original.UserSid -or $current.SessionId -ne $original.SessionId -or $current.ConnectionKind -cne $original.ConnectionKind){throw 'Proxy recovery identity differs from the original machine/user/session/scope.'}
  if(($current.Flags -band $mask) -ne ($expectedFlags -band $mask)){throw 'A changed proxy flag conflicts with recovery.'}
  if($expected.OwnsUrl -and -not [string]::Equals($current.AutoConfigUrl,$expected.ExpectedUrl,[StringComparison]::Ordinal)){throw 'The changed setup-script URL conflicts with recovery.'}
  [uint32]$unownedMask=[uint32]::MaxValue -bxor $mask
  [uint32]$restoredFlags=($current.Flags -band $unownedMask) -bor ($original.Flags -band $mask)
  $restoredUrl=if($expected.OwnsUrl){$original.AutoConfigUrl}else{$current.AutoConfigUrl}
  [pscustomobject]@{
    SchemaVersion=1;Kind='UserProxyRecoveryPreparation'
    DesiredValues=[pscustomobject]@{Flags=$restoredFlags;ProxyServer=$current.ProxyServer;ProxyBypass=$current.ProxyBypass;AutoConfigUrl=$restoredUrl}
    ChangeRequired=($restoredFlags -ne $current.Flags -or -not [string]::Equals($restoredUrl,$current.AutoConfigUrl,[StringComparison]::Ordinal))
    ReadyForMutation=$false;MutationAuthorized=$false;PolicyStatus='NotInspected';EffectiveRoutingVerified=$false
    Limitation='Supplied-data recovery only; live setter, refresh, durable state and native acceptance are not implemented'
  }
}

Export-ModuleMember -Function New-RideUserProxyConfigurationPatch,Restore-RideUserProxyConfigurationPatch
