<#
.SYNOPSIS
  Apply and restore prepared default/LAN WinINet proxy edits with fresh checks.
.DESCRIPTION
  Binds a supplied preparation snapshot to the intended interactive identity,
  compares the current literal configuration before writing, delegates the
  ShouldProcess-gated native setter, then reads back and reports partial outcomes.
  The module persists a create-new user-scope snapshot before applying a proxy patch;
  callers can supply their engine run ID so restore completion follows the same run.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Inputs: Supplied proxy preparation snapshot and explicit current machine/SID/session.
  Recovery: Returns the original preparation snapshot for caller-managed retention.
  A pre-write compare is not atomic. Partial outcomes require inspection before retry.
  Version: 0.4.0.
  Changelog: 0.4.0: Allow the engine run ID to own proxy state and restore completion.
  0.3.0: Track saved-run restore completion and refuse stale retries.
  0.2.0: Persist pre-change user state and restore it by saved run ID.
  0.1.0: Add identity-bound fresh-compare apply and conflict-aware restore candidate.
.LINK
  ../docs/user-proxy-inventory.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.UserProxyInventory.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.UserProxyPreparation.psm1') -Force -ErrorAction Stop

function Test-RideUserProxyLifecycleValueEqual {
  param($Left,$Right)
  $Left.ComputerName -ieq $Right.ComputerName -and
    $Left.UserSid -ceq $Right.UserSid -and
    [int]$Left.SessionId -eq [int]$Right.SessionId -and
    (Test-RideUserProxyLifecycleConfigurationEqual $Left $Right)
}

function Test-RideUserProxyLifecycleConfigurationEqual {
  param($Left,$Right)
  [uint32]$Left.Flags -eq [uint32]$Right.Flags -and
    [string]::Equals($Left.ProxyServer,$Right.ProxyServer,[StringComparison]::Ordinal) -and
    [string]::Equals($Left.ProxyBypass,$Right.ProxyBypass,[StringComparison]::Ordinal) -and
    [string]::Equals($Left.AutoConfigUrl,$Right.AutoConfigUrl,[StringComparison]::Ordinal)
}

function Get-RideUserProxyLifecycleStateDirectory {
  Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RIDE/State/UserProxy'
}

function Save-RideUserProxyLifecycleSnapshot {
  param($Snapshot,[string]$RunId)
  if($null -eq $Snapshot -or $Snapshot.SchemaVersion -ne 1 -or $Snapshot.Kind -cne 'UserProxyPreparationSnapshot' -or $null -eq $Snapshot.Original){throw 'Invalid proxy preparation snapshot.'}
  $directory=Get-RideUserProxyLifecycleStateDirectory
  New-Item -ItemType Directory -Path $directory -Force|Out-Null
  $directoryItem=Get-Item -LiteralPath $directory -Force
  if($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Proxy state directory cannot be a reparse point.'}
  if(-not $RunId){$RunId=[guid]::NewGuid().ToString('N')}elseif($RunId -notmatch '^[0-9a-fA-F]{32}$'){throw 'RunId must be a 32-character hexadecimal saved proxy ID.'}else{$RunId=$RunId.ToLowerInvariant()}
  $path=Join-Path $directory ($RunId+'.json')
  $record=[pscustomobject]@{SchemaVersion=1;Kind='UserProxyLifecycleState';RunId=$RunId;CreatedAtUtc=[DateTime]::UtcNow.ToString('o');ComputerName=$Snapshot.Original.ComputerName;UserSid=$Snapshot.Original.UserSid;SessionId=[int]$Snapshot.Original.SessionId;Snapshot=$Snapshot}
  $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject $record -Depth 12 -Compress))
  if($bytes.Length -gt 65536){throw 'Proxy lifecycle snapshot exceeds 64 KiB.'}
  $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  [pscustomobject]@{RunId=$RunId;Path=$path}
}

function Get-RideUserProxyLifecycleSnapshot {
  param([string]$RunId,[string]$ComputerName,[string]$UserSid,[int]$SessionId)
  if($RunId -notmatch '^[0-9a-fA-F]{32}$'){throw 'RunId must be a 32-character hexadecimal saved proxy ID.'}
  $RunId=$RunId.ToLowerInvariant()
  $path=Join-Path (Get-RideUserProxyLifecycleStateDirectory) ($RunId+'.json')
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw 'Saved proxy lifecycle state was not found.'}
  $item=Get-Item -LiteralPath $path -Force
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 65536){throw 'Saved proxy lifecycle state path or size is invalid.'}
  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
  try{$bytes=[byte[]]::new([int]$stream.Length);$offset=0;while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'Saved proxy lifecycle state changed while being read.'};$offset+=$count}}finally{$stream.Dispose()}
  $record=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json -ErrorAction Stop
  if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'UserProxyLifecycleState' -or $record.RunId -cne $RunId -or $record.ComputerName -ine $ComputerName -or $record.UserSid -cne $UserSid -or [int]$record.SessionId -ne $SessionId -or $null -eq $record.Snapshot -or $record.Snapshot.Original.ComputerName -ine $ComputerName -or $record.Snapshot.Original.UserSid -cne $UserSid -or [int]$record.Snapshot.Original.SessionId -ne $SessionId){throw 'Saved proxy lifecycle state does not match the intended machine/user/session.'}
  $record.Snapshot
}

function Get-RideUserProxyLifecycleCompletion {
  param([string]$RunId,[string]$ComputerName,[string]$UserSid,[int]$SessionId)
  $RunId=$RunId.ToLowerInvariant()
  $path=Join-Path (Get-RideUserProxyLifecycleStateDirectory) ($RunId+'.completed.json')
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){return $null}
  $item=Get-Item -LiteralPath $path -Force
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 8192){throw 'Saved proxy completion record path or size is invalid.'}
  $record=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json -ErrorAction Stop
  if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'UserProxyLifecycleCompletion' -or $record.RunId -cne $RunId -or $record.Status -cne 'Restored' -or $record.ComputerName -ine $ComputerName -or $record.UserSid -cne $UserSid -or [int]$record.SessionId -ne $SessionId){throw 'Saved proxy completion record does not match the intended machine/user/session.'}
  $record
}

function Save-RideUserProxyLifecycleCompletion {
  param([string]$RunId,[string]$ComputerName,[string]$UserSid,[int]$SessionId)
  $RunId=$RunId.ToLowerInvariant()
  $directory=Get-RideUserProxyLifecycleStateDirectory
  $path=Join-Path $directory ($RunId+'.completed.json')
  $record=[pscustomobject]@{SchemaVersion=1;Kind='UserProxyLifecycleCompletion';RunId=$RunId;Status='Restored';CompletedAtUtc=[DateTime]::UtcNow.ToString('o');ComputerName=$ComputerName;UserSid=$UserSid;SessionId=$SessionId}
  $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject $record -Depth 4 -Compress))
  if($bytes.Length -gt 8192){throw 'Proxy completion record exceeds 8 KiB.'}
  $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  $path
}

function Get-RideUserProxyLifecycleObservation {
  param([string]$ComputerName,[string]$UserSid,[int]$SessionId)
  Get-RideUserProxyObservation -ExpectedComputerName $ComputerName -ExpectedUserSid $UserSid -ExpectedSessionId $SessionId -ConnectionKind DefaultLan
}

function Invoke-RideUserProxyLifecycleWrite {
  param($Expected,$Desired,$Snapshot,[string]$ComputerName,[string]$UserSid,[int]$SessionId,[switch]$NoCompensation)
  $current=Get-RideUserProxyLifecycleObservation -ComputerName $ComputerName -UserSid $UserSid -SessionId $SessionId
  if(-not (Test-RideUserProxyLifecycleValueEqual $current $Expected)){throw 'Proxy configuration changed since preparation; refusing to overwrite it.'}
  $policy=Get-RideUserProxyPolicyObservation
  if($policy.KnownPolicyStatus -cne 'Clear'){throw "Proxy write refused because documented policy status is $($policy.KnownPolicyStatus)."}
  $ownsUrl=-not [string]::Equals($Expected.AutoConfigUrl,$Desired.AutoConfigUrl,[StringComparison]::Ordinal)
  try{$write=Set-RideUserProxyNativeConfiguration -Flags ([uint32]$Desired.Flags) -AutoConfigUrl $Desired.AutoConfigUrl -OwnsAutoConfigUrl $ownsUrl -ExpectedComputerName $ComputerName -ExpectedUserSid $UserSid -ExpectedSessionId $SessionId -Confirm:$false}
  catch{
    $writeError=$_.Exception.Message
    try{$observed=Get-RideUserProxyLifecycleObservation -ComputerName $ComputerName -UserSid $UserSid -SessionId $SessionId}
    catch{return [pscustomobject]@{Status='WriteFailedUnverified';Changed=$null;ReadbackMatched=$false;WriteResult=$null;CompensationResult=$null;Current=$null;Snapshot=$Snapshot;Limitation="Native setter threw and follow-up observation failed: $writeError"}}
    if((Test-RideUserProxyLifecycleConfigurationEqual $observed $Expected)){return [pscustomobject]@{Status='NotApplied';Changed=$false;ReadbackMatched=$true;WriteResult=$null;CompensationResult=$null;Current=$observed;Snapshot=$Snapshot;Limitation="Native setter failed before a configuration change: $writeError"}}
    if((Test-RideUserProxyLifecycleConfigurationEqual $observed $Desired) -and -not $NoCompensation){
      try{$compensation=Invoke-RideUserProxyLifecycleWrite -Expected $observed -Desired $Expected -Snapshot $Snapshot -ComputerName $ComputerName -UserSid $UserSid -SessionId $SessionId -NoCompensation}
      catch{return [pscustomobject]@{Status='CompensationIncomplete';Changed=$true;ReadbackMatched=$false;WriteResult=$null;CompensationResult=$null;Current=$observed;Snapshot=$Snapshot;Limitation="Native setter threw after the desired values appeared; compensation could not be completed: $writeError"}}
      if($compensation.Status -ceq 'Applied'){return [pscustomobject]@{Status='Compensated';Changed=$false;ReadbackMatched=$true;WriteResult=$null;CompensationResult=$compensation;Current=$compensation.Current;Snapshot=$Snapshot;Limitation="Native setter threw after the configuration changed; the prior state was restored and verified: $writeError"}}
      return [pscustomobject]@{Status='CompensationIncomplete';Changed=$true;ReadbackMatched=$false;WriteResult=$null;CompensationResult=$compensation;Current=$compensation.Current;Snapshot=$Snapshot;Limitation="Native setter threw and exact compensation did not verify: $writeError"}
    }
    return [pscustomobject]@{Status='WriteFailedMismatch';Changed=$true;ReadbackMatched=$false;WriteResult=$null;CompensationResult=$null;Current=$observed;Snapshot=$Snapshot;Limitation="Native setter threw and current values do not match either complete state; no overwrite was attempted: $writeError"}
  }
  if(-not $write.ConfigurationSet){
    try{$observed=Get-RideUserProxyLifecycleObservation -ComputerName $ComputerName -UserSid $UserSid -SessionId $SessionId}
    catch{return [pscustomobject]@{Status='WriteFailedUnverified';Changed=$null;ReadbackMatched=$false;WriteResult=$write;CompensationResult=$null;Current=$null;Snapshot=$Snapshot;Limitation='Native configuration setter reported failure and readback failed. Inspect the target before retrying.'}}
    if(Test-RideUserProxyLifecycleValueEqual $observed $Expected){return [pscustomobject]@{Status='NotApplied';Changed=$false;ReadbackMatched=$true;WriteResult=$write;CompensationResult=$null;Current=$observed;Snapshot=$Snapshot;Limitation='Native configuration setter reported failure and readback confirms the prior state remains.'}}
    if((Test-RideUserProxyLifecycleConfigurationEqual $observed $Desired) -and -not $NoCompensation){
      try{$compensation=Invoke-RideUserProxyLifecycleWrite -Expected $observed -Desired $Expected -Snapshot $Snapshot -ComputerName $ComputerName -UserSid $UserSid -SessionId $SessionId -NoCompensation}
      catch{return [pscustomobject]@{Status='CompensationIncomplete';Changed=$true;ReadbackMatched=$false;WriteResult=$write;CompensationResult=$null;Current=$observed;Snapshot=$Snapshot;Limitation='Configuration setter reported failure after the desired state appeared; compensation was refused.'}}
      if($compensation.Status -ceq 'Applied'){return [pscustomobject]@{Status='Compensated';Changed=$false;ReadbackMatched=$true;WriteResult=$write;CompensationResult=$compensation;Current=$compensation.Current;Snapshot=$Snapshot;Limitation='Configuration setter reported failure after values changed; the prior state was restored and verified.'}}
      return [pscustomobject]@{Status='CompensationIncomplete';Changed=$true;ReadbackMatched=$false;WriteResult=$write;CompensationResult=$compensation;Current=$compensation.Current;Snapshot=$Snapshot;Limitation='Configuration setter reported failure and compensation did not verify.'}
    }
    return [pscustomobject]@{Status='WriteFailedMismatch';Changed=$true;ReadbackMatched=$false;WriteResult=$write;CompensationResult=$null;Current=$observed;Snapshot=$Snapshot;Limitation='Configuration setter reported failure and values match neither complete pre-write nor requested state; no overwrite was attempted.'}
  }
  try{$after=Get-RideUserProxyLifecycleObservation -ComputerName $ComputerName -UserSid $UserSid -SessionId $SessionId}
  catch{
    try{$after=Get-RideUserProxyLifecycleObservation -ComputerName $ComputerName -UserSid $UserSid -SessionId $SessionId}
    catch{return [pscustomobject]@{Status='AppliedUnverified';Changed=$true;ReadbackMatched=$false;WriteResult=$write;CompensationResult=$null;Current=$null;Snapshot=$Snapshot;Limitation='The native setter reported success, but two readback attempts failed. Inspect the current target before retrying or restoring.'}}
  }
  $readbackMatched=Test-RideUserProxyLifecycleConfigurationEqual $after $Desired
  if(-not $readbackMatched){return [pscustomobject]@{Status='AppliedMismatch';Changed=$true;ReadbackMatched=$false;WriteResult=$write;CompensationResult=$null;Current=$after;Snapshot=$Snapshot;Limitation='Post-write values differ from the requested state. Do not overwrite conflicting current data; inspect the retained snapshot.'}}
  if((-not $write.SettingsChangedNotified -or -not $write.Refreshed) -and -not $NoCompensation){
    try{$compensation=Invoke-RideUserProxyLifecycleWrite -Expected $after -Desired $Expected -Snapshot $Snapshot -ComputerName $ComputerName -UserSid $UserSid -SessionId $SessionId -NoCompensation}
    catch{return [pscustomobject]@{Status='AppliedRefreshIncomplete';Changed=$true;ReadbackMatched=$true;WriteResult=$write;CompensationResult=$null;Current=$after;Snapshot=$Snapshot;Limitation='Requested values are present but notification failed; exact compensation was refused because the current state or policy changed.'}}
    if($compensation.Status -ceq 'Applied'){return [pscustomobject]@{Status='Compensated';Changed=$false;ReadbackMatched=$true;WriteResult=$write;CompensationResult=$compensation;Current=$compensation.Current;Snapshot=$Snapshot;Limitation='Notification failed after the initial write; the prior literal configuration was restored and verified.'}}
    return [pscustomobject]@{Status='CompensationIncomplete';Changed=$true;ReadbackMatched=$false;WriteResult=$write;CompensationResult=$compensation;Current=$compensation.Current;Snapshot=$Snapshot;Limitation='Notification failed and automatic compensation did not verify. Inspect current values and retained snapshot before further action.'}
  }
  if(-not $write.SettingsChangedNotified -or -not $write.Refreshed){return [pscustomobject]@{Status='AppliedRefreshIncomplete';Changed=$true;ReadbackMatched=$true;WriteResult=$write;CompensationResult=$null;Current=$after;Snapshot=$Snapshot;Limitation='Compensation did not complete; requested values remain present but one or more notifications failed.'}}
  [pscustomobject]@{Status='Applied';Changed=$true;ReadbackMatched=$true;WriteResult=$write;Current=$after;Snapshot=$Snapshot;Limitation='The pre-write comparison is not atomic; snapshot persistence remains the caller responsibility.'}
}

function Set-RideUserProxyConfigurationPatch {
  <#
  .SYNOPSIS
    Apply a prepared default/LAN proxy configuration patch.
  .DESCRIPTION
    Reconstructs and validates the preparation, checks the exact current
    configuration and documented policy values, then writes only changed flags
    and an owned PAC URL. Reads the resulting values back and reports partial
    outcomes without hiding them or retrying automatically.
  .PARAMETER Patch
    Version-1 result from New-RideUserProxyConfigurationPatch.
  .PARAMETER ExpectedComputerName
    Intended current local machine name.
  .PARAMETER ExpectedUserSid
    Intended interactive user SID.
  .PARAMETER ExpectedSessionId
    Intended nonzero interactive session.
  .EXAMPLE
    Set-RideUserProxyConfigurationPatch -Patch $patch -ExpectedComputerName $env:COMPUTERNAME -ExpectedUserSid $sid -ExpectedSessionId $session -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject with status, literal readback, write results and retained preparation snapshot.
  .NOTES
    The user-scope snapshot is not authenticated and restore completion is not tracked.
    Atomic compare-and-set and engine integration are not provided. No PAC fetch,
    WinHTTP access or effective-route verification is performed.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param(
    [Parameter(Mandatory)]$Patch,
    [string]$RunId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9]+(?:-[0-9]+)+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  if($null -eq $Patch.Snapshot -or $Patch.SchemaVersion -ne 1 -or $Patch.Kind -cne 'UserProxyPreparation' -or $Patch.ChangeRequired -isnot [bool]){throw 'Invalid proxy preparation patch.'}
  $snapshot=$Patch.Snapshot
  $arguments=@{Observation=$snapshot.Original;AutomaticDetection=$snapshot.AutomaticDetection;SetupScript=$snapshot.SetupScript}
  if($snapshot.HasScriptUrl){$arguments.ScriptUrl=$snapshot.ScriptUrl}
  $reconstructed=New-RideUserProxyConfigurationPatch @arguments
  if($reconstructed.Snapshot.OwnedFlagMask -ne $snapshot.OwnedFlagMask -or $reconstructed.Snapshot.OwnsUrl -ne $snapshot.OwnsUrl -or $reconstructed.Snapshot.ExpectedFlags -ne $snapshot.ExpectedFlags -or -not [string]::Equals($reconstructed.Snapshot.ExpectedUrl,$snapshot.ExpectedUrl,[StringComparison]::Ordinal)){throw 'Proxy preparation patch does not match its reconstructed snapshot.'}
  if(-not $reconstructed.ChangeRequired){return [pscustomobject]@{Status='NoChange';Changed=$false;ReadbackMatched=$true;WriteResult=$null;CompensationResult=$null;Current=$snapshot.Original;Snapshot=$snapshot;Limitation='The prepared values already match; no WinINet query or setter is needed.'}}
  $expected=$snapshot.Original
  if($expected.ComputerName -ine $ExpectedComputerName -or $expected.UserSid -cne $ExpectedUserSid -or $expected.SessionId -ne $ExpectedSessionId){throw 'Proxy patch identity differs from the explicitly intended machine/user/session.'}
  $desired=$Patch.DesiredValues
  if($desired.Flags -ne $snapshot.ExpectedFlags -or -not [string]::Equals($desired.AutoConfigUrl,$snapshot.ExpectedUrl,[StringComparison]::Ordinal) -or -not [string]::Equals($desired.ProxyServer,$expected.ProxyServer,[StringComparison]::Ordinal) -or -not [string]::Equals($desired.ProxyBypass,$expected.ProxyBypass,[StringComparison]::Ordinal)){throw 'Proxy patch desired values disagree with its snapshot.'}
  $current=Get-RideUserProxyLifecycleObservation -ComputerName $ExpectedComputerName -UserSid $ExpectedUserSid -SessionId $ExpectedSessionId
  if(-not (Test-RideUserProxyLifecycleValueEqual $current $expected)){throw 'Proxy configuration changed since preparation; refusing to overwrite it.'}
  $policy=Get-RideUserProxyPolicyObservation
  if($policy.KnownPolicyStatus -cne 'Clear'){throw "Proxy write refused because documented policy status is $($policy.KnownPolicyStatus)."}
  $target="$ExpectedComputerName / $ExpectedUserSid / session $ExpectedSessionId / DefaultLan"
  if(-not $PSCmdlet.ShouldProcess($target,'Apply prepared WinINet proxy configuration patch')){return [pscustomobject]@{Status='WhatIf';Changed=$false;ReadbackMatched=$false;WriteResult=$null;Current=$current;Snapshot=$snapshot;Limitation='No WinINet setter was called.'}}
  $saved=Save-RideUserProxyLifecycleSnapshot -Snapshot $snapshot -RunId $RunId
  $result=Invoke-RideUserProxyLifecycleWrite -Expected $expected -Desired $desired -Snapshot $snapshot -ComputerName $ExpectedComputerName -UserSid $ExpectedUserSid -SessionId $ExpectedSessionId
  $result|Add-Member -NotePropertyName RunId -NotePropertyValue $saved.RunId -Force
  $result|Add-Member -NotePropertyName SnapshotPath -NotePropertyValue $saved.Path -Force
  $result
}

function Restore-RideUserProxyConfigurationSnapshot {
  <#
  .SYNOPSIS
    Restore the owned bits and URL from a retained proxy preparation snapshot.
  .DESCRIPTION
    Captures the fresh current default/LAN values, prepares conflict-aware
    recovery, compares that observation again immediately before the write and
    verifies the post-write values. Unowned current flags and strings are retained.
  .PARAMETER Snapshot
    In-memory preparation snapshot returned by Set-RideUserProxyConfigurationPatch.
  .PARAMETER RunId
    Saved user-scope run ID returned by Set-RideUserProxyConfigurationPatch.
  .PARAMETER ExpectedComputerName
    Intended current local machine name.
  .PARAMETER ExpectedUserSid
    Intended interactive user SID.
  .PARAMETER ExpectedSessionId
    Intended nonzero interactive session.
  .EXAMPLE
    Restore-RideUserProxyConfigurationSnapshot -RunId $result.RunId -ExpectedComputerName $env:COMPUTERNAME -ExpectedUserSid $sid -ExpectedSessionId $session -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject with status, literal readback and recovery results.
  .NOTES
    The saved state and completion marker are user-writable and schema-validated,
    not authenticated. RunId restores track completion and refuse repeated writes
    after drift, but there is no atomic compare-and-set or engine/catalog integration.
    Partial outcomes require inspection; no automatic retry or compensation occurs.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName='Snapshot')]
  param(
    [Parameter(Mandatory,ParameterSetName='Snapshot')]$Snapshot,
    [Parameter(Mandatory,ParameterSetName='RunId')][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9]+(?:-[0-9]+)+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  if($PSCmdlet.ParameterSetName -eq 'RunId'){$RunId=$RunId.ToLowerInvariant();$Snapshot=Get-RideUserProxyLifecycleSnapshot -RunId $RunId -ComputerName $ExpectedComputerName -UserSid $ExpectedUserSid -SessionId $ExpectedSessionId}
  if($null -eq $Snapshot.Original -or $Snapshot.Kind -cne 'UserProxyPreparationSnapshot' -or $Snapshot.SchemaVersion -ne 1){throw 'Invalid proxy preparation snapshot.'}
  if($Snapshot.Original.ComputerName -ine $ExpectedComputerName -or $Snapshot.Original.UserSid -cne $ExpectedUserSid -or $Snapshot.Original.SessionId -ne $ExpectedSessionId){throw 'Proxy snapshot identity differs from the explicitly intended machine/user/session.'}
  if($PSCmdlet.ParameterSetName -eq 'RunId'){
    $completion=Get-RideUserProxyLifecycleCompletion -RunId $RunId -ComputerName $ExpectedComputerName -UserSid $ExpectedUserSid -SessionId $ExpectedSessionId
    if($completion){
      $current=Get-RideUserProxyLifecycleObservation -ComputerName $ExpectedComputerName -UserSid $ExpectedUserSid -SessionId $ExpectedSessionId
      [uint32]$ownedMask=$Snapshot.OwnedFlagMask
      $restoredFlags=(([uint32]$current.Flags -band $ownedMask) -eq ([uint32]$Snapshot.Original.Flags -band $ownedMask))
      $restoredUrl=(-not $Snapshot.OwnsUrl -or [string]::Equals($current.AutoConfigUrl,$Snapshot.Original.AutoConfigUrl,[StringComparison]::Ordinal))
      if(-not $restoredFlags -or -not $restoredUrl){throw 'Proxy settings changed after recorded restoration; refusing to overwrite current values.'}
      return [pscustomobject]@{Status='AlreadyRestored';Changed=$false;ReadbackMatched=$true;WriteResult=$null;Current=$current;Snapshot=$Snapshot;RunId=$RunId;Limitation='The saved run is complete and its owned values still match the captured prior state.'}
    }
  }
  $current=Get-RideUserProxyLifecycleObservation -ComputerName $ExpectedComputerName -UserSid $ExpectedUserSid -SessionId $ExpectedSessionId
  $recovery=Restore-RideUserProxyConfigurationPatch -Observation $current -Snapshot $Snapshot
  if(-not $recovery.ChangeRequired){return [pscustomobject]@{Status='NoChange';Changed=$false;ReadbackMatched=$true;WriteResult=$null;Current=$current;Snapshot=$Snapshot;Limitation='No owned proxy change remains to restore.'}}
  $policy=Get-RideUserProxyPolicyObservation
  if($policy.KnownPolicyStatus -cne 'Clear'){throw "Proxy restore refused because documented policy status is $($policy.KnownPolicyStatus)."}
  $target="$ExpectedComputerName / $ExpectedUserSid / session $ExpectedSessionId / DefaultLan"
  if(-not $PSCmdlet.ShouldProcess($target,'Restore owned WinINet proxy configuration values')){return [pscustomobject]@{Status='WhatIf';Changed=$false;ReadbackMatched=$false;WriteResult=$null;Current=$current;Snapshot=$Snapshot;Limitation='No WinINet setter was called.'}}
  $result=Invoke-RideUserProxyLifecycleWrite -Expected $current -Desired $recovery.DesiredValues -Snapshot $Snapshot -ComputerName $ExpectedComputerName -UserSid $ExpectedUserSid -SessionId $ExpectedSessionId
  if($PSCmdlet.ParameterSetName -eq 'RunId' -and $result.Status -ceq 'Applied' -and $result.ReadbackMatched){
    try{$null=Save-RideUserProxyLifecycleCompletion -RunId $RunId -ComputerName $ExpectedComputerName -UserSid $ExpectedUserSid -SessionId $ExpectedSessionId}
    catch{$result.Status='AppliedCompletionUntracked';$result.Limitation='The proxy values were restored and verified, but the completion record could not be saved. Inspect state before retrying.'}
    $result|Add-Member -NotePropertyName RunId -NotePropertyValue $RunId -Force
  }
  $result
}

Export-ModuleMember -Function Set-RideUserProxyConfigurationPatch,Restore-RideUserProxyConfigurationSnapshot
