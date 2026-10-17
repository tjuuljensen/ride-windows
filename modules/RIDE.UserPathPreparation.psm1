<#
.SYNOPSIS
  Observe and prepare ownership-aware persistent user-bin PATH changes.
.DESCRIPTION
  Reads only the explicitly identified current user's literal Environment/Path.
  Preparation appends an absolute bin entry in memory and reconstructs version-1
  recovery without owning pre-existing entries. No registry/environment setter,
  profile execution, broadcast, directory creation or deletion is implemented.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Inputs: Explicit machine/SID/session for observation; supplied records for edits.
  Recovery: Data-only entry recovery; durable state, live conflict checks and
  environment refresh remain unimplemented. No catalog target is introduced.
  Version: 0.1.0.
  Changelog: 0.1.0: Add literal user PATH observation and append/recovery ownership.
.LINK
  ../docs/powershell-profiles.md
#>
$ErrorActionPreference='Stop'

function ConvertTo-RideUserPathContext {
  param($Context)
  if($Context.ComputerName -isnot [string] -or [string]::IsNullOrWhiteSpace($Context.ComputerName) -or $Context.ComputerName.Length -gt 255 -or $Context.ComputerName -match '[\x00-\x1f]' -or
    $Context.UserSid -isnot [string] -or $Context.SessionId -isnot [int] -and $Context.SessionId -isnot [long] -or $Context.SessionId -lt 1 -or $Context.SessionId -gt [int]::MaxValue -or
    $Context.UserInteractive -isnot [bool] -or -not $Context.UserInteractive -or $Context.NativeProcess -isnot [bool] -or -not $Context.NativeProcess){throw 'User PATH requires an explicit native interactive identity.'}
  try{$sid=[Security.Principal.SecurityIdentifier]::new($Context.UserSid)}catch{throw 'Invalid user PATH SID.'}
  if($sid.Value -cne $Context.UserSid){throw 'User PATH SID must be canonical.'}
  $profile=$Context.UserProfile
  if($profile -isnot [string] -or $profile.Length -gt 1024 -or $profile -cnotmatch '^[A-Za-z]:[\\/][^\\/]' -or $profile -match '[;"<>|?*%\x00-\x1f]' -or $profile.Substring(2).Contains(':') -or
    $profile -match '(^|[\\/])\.\.?([\\/]|$)' -or $profile -match '[. ]([\\/]|$)'){throw 'User PATH requires an unambiguous local profile directory.'}
  $profile=[IO.Path]::GetFullPath($profile).TrimEnd('\','/')
  [pscustomobject]@{ComputerName=$Context.ComputerName;UserSid=$sid.Value;SessionId=[int]$Context.SessionId;UserProfile=$profile;UserInteractive=$true;NativeProcess=$true}
}

function ConvertTo-RideUserPathValue {
  param($Value)
  if($Value.KeyExists -isnot [bool] -or $Value.Exists -isnot [bool] -or ($Value.Exists -and -not $Value.KeyExists)){throw 'Invalid user PATH existence record.'}
  if($Value.Exists){
    if($Value.Kind -cnotin @('String','ExpandString') -or $Value.Value -isnot [string] -or $Value.Value.Length -gt 32766 -or $Value.Value -match '[\x00-\x1f]'){throw 'User PATH must be bounded literal String or ExpandString data.'}
  }elseif($null -ne $Value.Kind -or $null -ne $Value.Value){throw 'Absent user PATH must retain null kind and data.'}
  [pscustomobject]@{KeyExists=$Value.KeyExists;Exists=$Value.Exists;Kind=$Value.Kind;Value=$Value.Value}
}

function ConvertTo-RideUserPathObservation {
  param($Observation)
  if(($Observation.SchemaVersion -isnot [int] -and $Observation.SchemaVersion -isnot [long]) -or $Observation.SchemaVersion -ne 1 -or $Observation.Kind -cne 'UserPathObservation' -or $Observation.Status -cne 'Captured' -or
    $Observation.ReadyForMutation -isnot [bool] -or $Observation.ReadyForMutation){throw 'Expected a captured read-only schema-1 user PATH observation.'}
  [pscustomobject]@{SchemaVersion=1;Kind='UserPathObservation';Status='Captured';Context=(ConvertTo-RideUserPathContext $Observation.Context);Path=(ConvertTo-RideUserPathValue $Observation.Path);ReadyForMutation=$false}
}

function Get-RideUserPathContext {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$process=[Diagnostics.Process]::GetCurrentProcess()
  try{[pscustomobject]@{ComputerName=[Environment]::MachineName;UserSid=$identity.User.Value;SessionId=$process.SessionId;UserProfile=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile);UserInteractive=[Environment]::UserInteractive;NativeProcess=([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)}}
  finally{$identity.Dispose();$process.Dispose()}
}

function Open-RideUserPathKey { [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment',$false) }

function Read-RideUserPathValue {
  $key=Open-RideUserPathKey
  try{
    if($null -eq $key){return [pscustomobject]@{KeyExists=$false;Exists=$false;Kind=$null;Value=$null}}
    $names=@($key.GetValueNames())
    if($names.Count -gt 4096){throw 'User environment exceeds the observation bound.'}
    $matches=@($names|Where-Object {$_ -ieq 'Path'})
    if($matches.Count -gt 1){throw 'Ambiguous user PATH registry identity.'}
    if(-not $matches.Count){return [pscustomobject]@{KeyExists=$true;Exists=$false;Kind=$null;Value=$null}}
    ConvertTo-RideUserPathValue ([pscustomobject]@{KeyExists=$true;Exists=$true;Kind=$key.GetValueKind($matches[0]).ToString();Value=$key.GetValue($matches[0],$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)})
  }finally{if($null -ne $key){$key.Dispose()}}
}

function Get-RideUserBinPathObservation {
  <#
  .SYNOPSIS
    Read literal persistent PATH for an explicitly identified current desktop user.
  .PARAMETER ExpectedComputerName
    Intended local computer; mismatches refuse before registry access.
  .PARAMETER ExpectedUserSid
    Intended current token SID. No alternate hive or user is queried.
  .PARAMETER ExpectedSessionId
    Positive intended interactive session identifier.
  .EXAMPLE
    Get-RideUserBinPathObservation -ExpectedComputerName 'TEST-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 literal observation, with no readiness claim.
  .NOTES
    Captures missing versus empty value and String versus ExpandString without
    expanding data through the process environment. Errors fail, never mean empty.
    Rechecks machine/SID/session/profile before returning. No bin existence query.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId)
  $before=ConvertTo-RideUserPathContext (Get-RideUserPathContext)
  if($before.ComputerName -ine $ExpectedComputerName -or $before.UserSid -cne $ExpectedUserSid -or $before.SessionId -ne $ExpectedSessionId){throw 'User PATH target differs from the explicitly intended machine/user/session.'}
  $value=Read-RideUserPathValue
  $after=ConvertTo-RideUserPathContext (Get-RideUserPathContext)
  foreach($name in @('ComputerName','UserSid','SessionId','UserProfile')){if($before.$name -ine $after.$name){throw 'User PATH context changed during observation.'}}
  ConvertTo-RideUserPathObservation ([pscustomobject]@{SchemaVersion=1;Kind='UserPathObservation';Status='Captured';Context=$before;Path=$value;ReadyForMutation=$false})
}

function Get-RideUserPathEntries {
  param($Value,[string]$UserProfile)
  if(-not $Value.Exists){return}
  $position=0
  foreach($literal in $Value.Value.Split([char]';')){
    # Equivalence is conservative; raw text is never rewritten by normalization.
    $candidate=$literal.Trim()
    if($candidate.StartsWith('"') -and $candidate.EndsWith('"') -and $candidate.Length -ge 2){$candidate=$candidate.Substring(1,$candidate.Length-2)}
    if($candidate.Contains('"')){throw 'User PATH entry needs quote review before ownership can be established.'}
    if($candidate.Contains('%')){
      if($Value.Kind -cne 'ExpandString'){throw 'Literal percent-bearing PATH entry needs expansion review.'}
      $candidate=[regex]::Replace($candidate,'(?i)%USERPROFILE%',[Text.RegularExpressions.MatchEvaluator]{param($m)$UserProfile})
      if($candidate.Contains('%')){throw 'User PATH has unresolved environment references; do not expand through the current process.'}
    }
    $normalized=$null
    if($candidate -match '^[A-Za-z]:[\\/]'){
      if($candidate -match '[<>|?*\x00-\x1f]' -or $candidate.Substring(2).Contains(':') -or $candidate -match '[. ]([\\/]|$)'){throw 'User PATH entry needs path review before ownership can be established.'}
      try{$normalized=[IO.Path]::GetFullPath($candidate).TrimEnd('\','/')}catch{throw 'User PATH entry cannot be normalized safely.'}
    }
    [pscustomobject]@{Literal=$literal;Normalized=$normalized;Position=$position}
    $position+=$literal.Length+1
  }
}

function Test-RideUserPathValueEqual {
  param($Left,$Right)
  $Left.Exists -eq $Right.Exists -and $Left.Kind -ceq $Right.Kind -and [string]::Equals($Left.Value,$Right.Value,[StringComparison]::Ordinal)
}

function New-RideUserBinPathPatch {
  <#
  .SYNOPSIS
    Prepare adding the identified user's absolute bin entry to persistent user PATH.
  .PARAMETER Observation
    Captured schema-1 user PATH observation, not the merged process PATH.
  .EXAMPLE
    New-RideUserBinPathPatch -Observation $savedUserPath
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. DesiredValue, Changed and reconstructable version-1 snapshot.
  .NOTES
    Existing equivalent entries remain unowned no-ops, including duplicates.
    Preserves raw separators, spelling and value type. Unknown variable expansions
    require review. Does not provision bin, modify machine/process PATH or broadcast.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Observation)
  $original=ConvertTo-RideUserPathObservation $Observation
  $entry=[IO.Path]::Combine($original.Context.UserProfile,'bin')
  $entries=@(Get-RideUserPathEntries $original.Path $original.Context.UserProfile)
  $existing=@($entries|Where-Object {$null -ne $_.Normalized -and $_.Normalized -ieq $entry})
  $desired=ConvertTo-RideUserPathValue $original.Path
  $owned=($existing.Count -eq 0)
  if($owned){
    $text=if($original.Path.Exists -and $original.Path.Value.Length){$original.Path.Value+';'+$entry}else{$entry}
    if($text.Length -gt 32766){throw 'Appending user-bin would exceed the PATH preparation limit.'}
    $desired=[pscustomobject]@{KeyExists=$true;Exists=$true;Kind=if($original.Path.Exists){$original.Path.Kind}else{'String'};Value=$text}
  }
  [pscustomobject]@{
    SchemaVersion=1;Kind='UserBinPathPreparation';Entry=$entry;DesiredValue=$desired;ChangeRequired=$owned
    Snapshot=[pscustomobject]@{SchemaVersion=1;Kind='UserBinPathSnapshot';Original=$original;Entry=$entry;OwnsEntry=$owned;ExpectedValue=$desired}
    ReadyForMutation=$false;MutationAuthorized=$false;DirectoryOwnership=$false;EffectivePathVerified=$false
  }
}

function Restore-RideUserBinPathPatch {
  <#
  .SYNOPSIS
    Prepare removing only the entry owned by a validated prior append operation.
  .PARAMETER Observation
    Current saved literal PATH for the same machine, user, session and profile.
  .PARAMETER Snapshot
    Version-1 snapshot from New-RideUserBinPathPatch; never a bare entry name.
  .EXAMPLE
    Restore-RideUserBinPathPatch -Observation $current -Snapshot $patch.Snapshot
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Proposed literal recovery, never a registry or filesystem write.
  .NOTES
    Exact expected data restores original existence/type/text. Unrelated edits can
    remain while one exact owned token is removed. Renamed/equivalent duplicates
    or changed value kind conflict. A pre-existing unowned entry is never removed.
    Logical snapshot validation is not authentication or proof a mutation occurred.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Observation,[Parameter(Mandatory)]$Snapshot)
  $current=ConvertTo-RideUserPathObservation $Observation
  if(($Snapshot.SchemaVersion -isnot [int] -and $Snapshot.SchemaVersion -isnot [long]) -or $Snapshot.SchemaVersion -ne 1 -or $Snapshot.Kind -cne 'UserBinPathSnapshot' -or $Snapshot.OwnsEntry -isnot [bool]){throw 'Invalid user-bin PATH snapshot.'}
  $reconstructed=New-RideUserBinPathPatch $Snapshot.Original
  $expected=ConvertTo-RideUserPathValue $Snapshot.ExpectedValue
  if($Snapshot.Entry -cne $reconstructed.Entry -or $Snapshot.OwnsEntry -ne $reconstructed.Snapshot.OwnsEntry -or -not (Test-RideUserPathValueEqual $expected $reconstructed.DesiredValue) -or $expected.KeyExists -ne $reconstructed.DesiredValue.KeyExists){throw 'User-bin PATH snapshot differs from its reconstructed edit.'}
  $original=$reconstructed.Snapshot.Original
  foreach($name in @('ComputerName','UserSid','SessionId','UserProfile')){if($current.Context.$name -ine $original.Context.$name){throw 'User-bin PATH recovery identity changed.'}}
  $desired=ConvertTo-RideUserPathValue $current.Path
  if($Snapshot.OwnsEntry){
    if(Test-RideUserPathValueEqual $current.Path $expected){
      $desired=ConvertTo-RideUserPathValue $original.Path
      # Recovery owns only the value, never deletion of the Environment key.
      $desired.KeyExists=$current.Path.KeyExists
    }elseif(-not (Test-RideUserPathValueEqual $current.Path $original.Path) -and $current.Path.Exists){
      if($current.Path.Kind -cne $expected.Kind){throw 'User PATH registry kind conflicts with recovery.'}
      $entries=@(Get-RideUserPathEntries $current.Path $current.Context.UserProfile)
      $matches=@($entries|Where-Object {$null -ne $_.Normalized -and $_.Normalized -ieq $Snapshot.Entry})
      if($matches.Count -gt 1 -or ($matches.Count -eq 1 -and $matches[0].Literal -cne $Snapshot.Entry)){throw 'Changed or duplicate user-bin entry conflicts with recovery.'}
      if($matches.Count -eq 1){
        $start=$matches[0].Position;$length=$matches[0].Literal.Length
        if($start -gt 0){$start--;$length++}elseif($length -lt $current.Path.Value.Length){$length++}
        $desired.Value=$current.Path.Value.Remove($start,$length)
      }
    }
  }
  [pscustomobject]@{SchemaVersion=1;Kind='UserBinPathRecoveryPreparation';DesiredValue=$desired;ChangeRequired=(-not (Test-RideUserPathValueEqual $current.Path $desired));ReadyForMutation=$false;MutationAuthorized=$false;DirectoryOwnership=$false;EffectivePathVerified=$false}
}

Export-ModuleMember -Function Get-RideUserBinPathObservation,New-RideUserBinPathPatch,Restore-RideUserBinPathPatch
