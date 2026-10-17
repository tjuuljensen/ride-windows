<#
.SYNOPSIS
  Observe an explicitly identified user's language list and selected overrides.
.DESCRIPTION
  Preserves supplied language ordering and literal input-method strings without
  rebuilding a list, installing languages or writing regional settings. Import
  and saved-data completion perform no Windows query. Separate explicit providers
  observe display-language and default-input overrides. This is not a restore record.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; International
  module/provider acceptance pending on each target. No elevation prompt.
  File/environment inputs: Expected machine/build/edition and user/session.
  Recovery: Read-only metadata; no setter or account/profile transition.
  Version: 0.2.0.
  Changelog: 0.2.0: Observe explicit UI-language and default-input overrides separately.
    0.1.0: Add bounded ordered language observations and saved-tag lookup.
.LINK
  ../docs/user-language-inventory.md
#>
$ErrorActionPreference='Stop'

function Get-RideUserLanguageContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $process=[Diagnostics.Process]::GetCurrentProcess()
  try {
    [pscustomobject]@{
      ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber
      EditionId=[string]$version.EditionID;UpdateBuildRevision=$version.UBR
      NativeProcess=([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)
      UserSid=$identity.User.Value;SessionId=$process.SessionId;UserInteractive=[Environment]::UserInteractive
    }
  }finally{$identity.Dispose();$process.Dispose()}
}

function Get-RideUserLanguageRows {
  International\Get-WinUserLanguageList -ErrorAction Stop
}

function ConvertTo-RideObservedLanguageTag {
  param($Value)
  if($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)){return $null}
  if($Value -isnot [string] -or $Value.Length -gt 128 -or $Value -cnotmatch '^[a-zA-Z]{2,8}(?:-[a-zA-Z0-9]{1,8})*$'){throw 'Invalid observed language tag.'}
  $Value
}

function ConvertTo-RideLanguageObservedBoolean {
  param($Value)
  if($null -eq $Value){return $null}
  if($Value -is [bool]){return $Value}
  if($Value -isnot [ValueType] -or $Value -notin @(0,1)){throw 'Invalid language boolean observation.'}
  [bool]$Value
}

function Get-RideUserLanguageInventory {
  <#
  .SYNOPSIS
    Capture language order and input-method metadata for the expected user/session.
  .PARAMETER ExpectedComputerName
    Intended local machine name; no remote enumeration.
  .PARAMETER ExpectedBuild
    Independently supplied exact Windows build.
  .PARAMETER ExpectedEditionId
    Intended Windows EditionID.
  .PARAMETER ExpectedUserSid
    Intended interactive execution account SID; no alternate-account query.
  .PARAMETER ExpectedSessionId
    Intended nonzero process session ID.
  .EXAMPLE
    Get-RideUserLanguageInventory -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 ordered observation; never mutation-ready.
  .NOTES
    Maximum 128 languages and 128 input-method strings per language. No hard provider
    timeout. Captured-empty differs from Unavailable; no first-language selection.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  $context=Get-RideUserLanguageContext
  if(-not $context.NativeProcess -or -not $context.UserInteractive -or $context.SessionId -ne $ExpectedSessionId -or $context.UserSid -ine $ExpectedUserSid -or $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId){throw 'Language inventory target differs from the expected native machine/build/edition/user/session.'}
  $started=[DateTime]::UtcNow.ToString('o');$status='Unavailable';$errorId=$null;$observed=$null
  try {
    $rows=[Collections.Generic.List[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Get-RideUserLanguageRows | ForEach-Object {
      if($rows.Count -ge 128){throw 'Language inventory exceeds the 128-row bound.'}
      $tag=ConvertTo-RideObservedLanguageTag $_.LanguageTag
      if($tag -and -not $seen.Add($tag)){throw 'Duplicate observed language tag.'}
      $tips=$null
      if($null -ne $_.InputMethodTips){
        if($_.InputMethodTips -is [string] -or $_.InputMethodTips -isnot [Collections.IEnumerable]){throw 'Input methods must be an ordered collection.'}
        $items=[Collections.Generic.List[string]]::new()
        foreach($tip in $_.InputMethodTips){
          if($items.Count -ge 128 -or $tip -isnot [string] -or [string]::IsNullOrEmpty($tip) -or $tip.Length -gt 2048 -or $tip -match '[\x00-\x1f]'){throw 'Invalid or excessive input-method observation.'}
          $items.Add($tip)
        }
        $tips=@($items.ToArray())
      }
      $rows.Add([pscustomobject]@{
        Position=$rows.Count;LanguageTag=$tag;IdentityStatus=$(if($tag){'Identified'}else{'Unavailable'})
        InputMethodTips=$tips;Handwriting=ConvertTo-RideLanguageObservedBoolean $_.Handwriting
        Spellchecking=ConvertTo-RideLanguageObservedBoolean $_.Spellchecking;Selected=$false
      })
    }
    $observed=@($rows.ToArray());$status='Captured'
  }catch{$errorId=$_.Exception.GetType().FullName;$observed=$null}
  $after=Get-RideUserLanguageContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','NativeProcess','UserSid','SessionId','UserInteractive')){if($after.$field -cne $context.$field){throw 'Language inventory target changed during collection; discard the observation.'}}
  [pscustomobject]@{
    SchemaVersion=1;Kind='UserLanguageObservation';WindowsContext=$context
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o');Status=$status;ErrorId=$errorId;Languages=$observed
    Coverage='Get-WinUserLanguageList order, tags, input methods and available handwriting/spellchecking flags only'
    Consistency='Sequential current-user observation; no installed language, active input, display override, format, system locale or policy proof'
    ReadyForMutation=$false;RecoverySupported=$false
  }
}

function Find-RideUserLanguageObservation {
  <#
  .SYNOPSIS
    Find a language tag in saved ordered observations without querying Windows.
  .PARAMETER Inventory
    Schema-1 observation or its JSON representation.
  .PARAMETER LanguageTag
    Explicit saved language tag. Completion reads identified saved rows only.
  .EXAMPLE
    Find-RideUserLanguageObservation -Inventory $saved -LanguageTag en-GB
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Observed, NotObserved or Unavailable; no inferred default.
  .NOTES
    Tag equality is case-insensitive. Names and list position are not replacement
    identities. This lookup does not prove installed language or keyboard capability.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $data=$fakeBoundParameters.Inventory
        if($data.SchemaVersion -ne 1 -or $data.Kind -cne 'UserLanguageObservation' -or $data.Status -cne 'Captured' -or @($data.Languages).Count -gt 128){return}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $prefix=([string]$wordToComplete).Trim("'",'"')
        foreach($row in @($data.Languages)){
          $tag=[string]$row.LanguageTag
          if($row.IdentityStatus -ceq 'Identified' -and $tag.Length -le 128 -and $tag -cmatch '^[a-zA-Z]{2,8}(?:-[a-zA-Z0-9]{1,8})*$' -and $tag.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($tag)){
            [Management.Automation.CompletionResult]::new(("'"+$tag+"'"),$tag,'ParameterValue',$tag)
          }
        }
      }catch{return}
    })][string]$LanguageTag)
  $tag=ConvertTo-RideObservedLanguageTag $LanguageTag
  if(-not $tag){throw 'Select a nonempty observed language tag.'}
  if($Inventory.SchemaVersion -ne 1 -or $Inventory.Kind -cne 'UserLanguageObservation' -or $Inventory.Status -cnotin @('Captured','Unavailable') -or @($Inventory.Languages).Count -gt 128){throw 'Invalid language observation schema.'}
  $match=$null;$status=$Inventory.Status
  if($Inventory.Status -ceq 'Unavailable'){
    if($null -ne $Inventory.Languages){throw 'Unavailable language provider cannot contain rows.'}
  }else{
    if($null -eq $Inventory.Languages){throw 'Captured language observation requires a row collection.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$index=0
    foreach($row in @($Inventory.Languages)){
      if($row.Position -is [bool] -or $row.Position -is [string] -or $null -eq $row.Position -or $row.Position -ne $index){throw 'Invalid saved language order.'}
      $rowTag=ConvertTo-RideObservedLanguageTag $row.LanguageTag
      if(($rowTag -and ($row.IdentityStatus -cne 'Identified' -or -not $seen.Add($rowTag))) -or (-not $rowTag -and ($row.IdentityStatus -cne 'Unavailable' -or $null -ne $row.LanguageTag))){throw 'Invalid or duplicate saved language identity.'}
      if($rowTag -and $rowTag -ieq $tag){$match=$row};$index++
    }
    $status=if($match){'Observed'}else{'NotObserved'}
  }
  [pscustomobject]@{LanguageTag=$tag;Status=$status;Observation=$match;WindowsContext=$Inventory.WindowsContext;Coverage=$Inventory.Coverage;ReadyForMutation=$false;RecoverySupported=$false}
}

function Get-RideUserLanguageOverrideRows {
  param([string]$Kind)
  switch($Kind){
    'DisplayLanguage' { International\Get-WinUILanguageOverride -ErrorAction Stop }
    'DefaultInputMethod' { International\Get-WinDefaultInputMethodOverride -ErrorAction Stop }
    default { throw 'Unknown user-language override kind.' }
  }
}

function Get-RideUserLanguageOverrideInventory {
  <#
  .SYNOPSIS
    Observe selected current-user display/input overrides independently of list order.
  .DESCRIPTION
    Each selected provider either completes with one value/no output, or reports
    Unavailable without partial data. No UI refresh, input switch or logoff occurs.
    A display override can be pending and does not prove the current display language.
  .PARAMETER Kind
    DisplayLanguage or DefaultInputMethod, selected explicitly without duplicates.
  .PARAMETER ExpectedComputerName
    Independently supplied target machine name; remote collection is not supported.
  .PARAMETER ExpectedBuild
    Exact expected Windows build number.
  .PARAMETER ExpectedEditionId
    Expected Windows EditionID.
  .PARAMETER ExpectedUserSid
    Intended interactive execution account SID.
  .PARAMETER ExpectedSessionId
    Intended nonzero process session ID.
  .EXAMPLE
    Get-RideUserLanguageOverrideInventory -Kind DisplayLanguage,DefaultInputMethod -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 override observation, separate from UserLanguageObservation.
  .NOTES
    Read-only; native provider/output-shape acceptance remains pending. No-output
    display query documents no override. Empty/no-output input-query interpretation
    stays unverified; it is never replaced with the first input method in a list.
    Each query is bounded to one row and a 128-character tag or 2048-character TIP.
    Native call duration is not bounded. Records are not complete recovery snapshots.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('DisplayLanguage','DefaultInputMethod')][string[]]$Kind,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  if(-not $Kind.Count){throw 'Select at least one user-language override provider.'}
  $selected=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($item in $Kind){if(-not $selected.Add($item)){throw 'Select each user-language override provider only once.'}}
  $context=Get-RideUserLanguageContext
  if(-not $context.NativeProcess -or -not $context.UserInteractive -or $context.SessionId -ne $ExpectedSessionId -or $context.UserSid -ine $ExpectedUserSid -or $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId){throw 'Language override target differs from the expected native machine/build/edition/user/session.'}
  $started=[DateTime]::UtcNow.ToString('o')
  $providers=@(foreach($item in $Kind){
    $providerKind=if($item -ieq 'DisplayLanguage'){'DisplayLanguage'}else{'DefaultInputMethod'}
    $result=[pscustomobject]@{Kind=$providerKind;Status='Unavailable';ObservationState=$null;OverrideState=$null;Value=$null;ErrorId=$null;EffectiveValueVerified=$false}
    try{
      $values=[Collections.Generic.List[object]]::new()
      Get-RideUserLanguageOverrideRows -Kind $providerKind | ForEach-Object {
        if($null -eq $_){throw 'Unexpected null override row.'}
        if($values.Count -ge 1){throw 'Override provider returned multiple rows.'}
        $field=if($providerKind -ceq 'DisplayLanguage'){'Name'}else{'InputMethodTip'}
        $property=$_.PSObject.Properties[$field]
        if($null -eq $property -or $property.Value -isnot [string]){throw 'Missing or invalid override value.'}
        $value=$property.Value
        if($providerKind -ceq 'DisplayLanguage'){
          if([string]::IsNullOrEmpty($value)){throw 'Empty display override row is not a documented absence.'}
          if(-not (ConvertTo-RideObservedLanguageTag $value)){throw 'Blank display override value.'}
        }elseif($value.Length -gt 2048 -or $value -match '[\x00-\x1f]' -or ($value.Length -gt 0 -and [string]::IsNullOrWhiteSpace($value))){
          throw 'Invalid input-method override value.'
        }
        $values.Add($value)
      }
      if($values.Count -eq 0){
        $result.ObservationState='NoValueReturned'
        $result.OverrideState=if($providerKind -ceq 'DisplayLanguage'){'NotSet'}else{'Unverified'}
      }else{
        $result.Value=$values[0]
        $result.ObservationState=if($values[0].Length){'ValueReturned'}else{'EmptyValueReturned'}
        $result.OverrideState=if($values[0].Length){'Explicit'}else{'Unverified'}
      }
      $result.Status='Captured'
    }catch{
      $result.ErrorId=$_.Exception.GetType().FullName
      $result.Value=$null;$result.ObservationState=$null;$result.OverrideState=$null
    }
    $result
  })
  $after=Get-RideUserLanguageContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','NativeProcess','UserSid','SessionId','UserInteractive')){if($after.$field -cne $context.$field){throw 'Language override target changed during collection; discard the observation.'}}
  [pscustomobject]@{
    SchemaVersion=1;Kind='UserLanguageOverrideObservation';WindowsContext=$context
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o');Providers=$providers
    Coverage='Only explicitly selected current-user UI-language/default-input override providers'
    Consistency='Sequential observation; no current UI, active keyboard, installed language/input, desktop ownership or effective policy proof'
    ReadyForMutation=$false;RecoverySupported=$false
  }
}

Export-ModuleMember -Function Get-RideUserLanguageInventory,Find-RideUserLanguageObservation,Get-RideUserLanguageOverrideInventory
