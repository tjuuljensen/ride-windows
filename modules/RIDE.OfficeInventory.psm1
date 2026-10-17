<#
.SYNOPSIS
  Observe bounded Click-to-Run metadata through explicit registry views.
.DESCRIPTION
  Reads only eight reviewed machine configuration values. Does not query activation,
  product keys, account tokens, MSI providers or executable paths. Registry views
  remain separate and channel URLs are redacted except for a recognized Microsoft
  CDN channel GUID. Registration metadata does not establish installed products.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Read access to machine metadata; expected interactive user/session.
  Recovery: Read-only schema-1 observation, not a backup or deployment authority.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded/redacted Click-to-Run observation contract.
.LINK
  ../docs/application-packages.md
#>
$ErrorActionPreference='Stop'
$script:OfficeRoot='SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
$script:OfficeFields=@('VersionToReport','ClientVersionToReport','Platform','ProductReleaseIds','ClientCulture','CDNBaseUrl','UpdateChannel','AudienceId')

function Get-RideOfficeContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$process=[Diagnostics.Process]::GetCurrentProcess()
  try{
    [pscustomobject]@{
      ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID
      UpdateBuildRevision=$version.UBR;Is64BitOperatingSystem=[Environment]::Is64BitOperatingSystem
      NativeProcess=([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)
      UserSid=$identity.User.Value;SessionId=$process.SessionId;UserInteractive=[Environment]::UserInteractive
    }
  }finally{$identity.Dispose();$process.Dispose()}
}

function Open-RideOfficeBaseKey {
  param([string]$RegistryView)
  [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]$RegistryView)
}

function Get-RideOfficeSource {
  param([string]$RegistryView)
  $base=$null;$root=$null
  try{
    $base=Open-RideOfficeBaseKey -RegistryView $RegistryView
    $root=$base.OpenSubKey($script:OfficeRoot,$false)
    if($null -eq $root){return [pscustomobject]@{RootExists=$false;Values=$null}}
    $present=@($root.GetValueNames());$values=[ordered]@{}
    foreach($field in $script:OfficeFields){
      $exists=$present -icontains $field;$kind=$null;$value=$null
      if($exists){$kind=$root.GetValueKind($field).ToString();$value=$root.GetValue($field,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
      $values[$field]=[pscustomobject]@{Exists=$exists;Kind=$kind;Value=$value}
    }
    [pscustomobject]@{RootExists=$true;Values=[pscustomobject]$values}
  }finally{try{if($null -ne $root){$root.Dispose()}}finally{if($null -ne $base){$base.Dispose()}}}
}

function ConvertTo-RideOfficeSource {
  param($Source)
  if($Source.RootExists -isnot [bool]){throw 'Missing Click-to-Run root presence.'}
  if(-not $Source.RootExists){
    if($null -ne $Source.Values){throw 'Absent Click-to-Run root has data.'}
    return [pscustomobject]@{RootExists=$false;Values=$null}
  }
  $values=[ordered]@{}
  foreach($field in $script:OfficeFields){
    $raw=$Source.Values.$field
    if($raw.Exists -isnot [bool]){throw 'Missing Click-to-Run value presence.'}
    $kind=$null;$value=$null;$channelId=$null;$urlClass=$null
    $urlField=$field -in @('CDNBaseUrl','UpdateChannel')
    if(-not $raw.Exists){
      if($null -ne $raw.Kind -or $null -ne $raw.Value){throw 'Absent Click-to-Run value has data.'}
    }else{
      $kind=$raw.Kind
      if($kind -cnotin @('String','ExpandString') -or $raw.Value -isnot [string] -or $raw.Value.Length -gt 4096 -or $raw.Value -match '[\x00-\x1f]'){throw 'Invalid or excessive Click-to-Run metadata.'}
      if($urlField){
        $urlClass='OtherOrUnrecognized'
        # Exact spelling excludes credentials, ports, queries, fragments and expansion.
        if($kind -ceq 'String' -and $raw.Value -imatch '^https?://officecdn\.microsoft\.com/pr/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/?$'){
          $guid=[guid]$Matches[1]
          if($guid -ne [guid]::Empty){$channelId=$guid.ToString('D');$urlClass='MicrosoftOfficeCdn'}
        }
      }else{
        if($raw.Value -cnotmatch '^[A-Za-z0-9., _%{}-]*$'){throw 'Unrecognized Click-to-Run token data.'}
        $value=$raw.Value
      }
    }
    $values[$field]=[pscustomobject]@{Exists=$raw.Exists;Kind=$kind;Value=$value;ValueRedacted=($urlField -and $raw.Exists);UrlClass=$urlClass;MicrosoftChannelGuid=$channelId}
  }
  [pscustomobject]@{RootExists=$true;Values=[pscustomobject]$values}
}

function Get-RideOfficeInventory {
  <#
  .SYNOPSIS
    Collect Click-to-Run metadata under an independently expected execution identity.
  .PARAMETER ExpectedComputerName
    Expected local machine name.
  .PARAMETER ExpectedBuild
    Expected Windows build number.
  .PARAMETER ExpectedEditionId
    Expected Windows EditionID.
  .PARAMETER ExpectedUserSid
    Intended interactive execution account SID, including for these machine reads.
  .PARAMETER ExpectedSessionId
    Expected nonzero process session ID.
  .EXAMPLE
    Get-RideOfficeInventory -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 OfficeClickToRunObservation with separate registry views.
  .NOTES
    Queries Registry64 and Registry32 on 64-bit Windows, Registry32 otherwise.
    Missing keys are observed absence, not proof Office is absent. Failed/partial
    sources are Unavailable; unrelated views remain visible. Sequential reads are
    not atomic. No policy precedence, per-product language inventory, MSI inventory,
    license edition/entitlement, activation, installer or filesystem check occurs.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateLength(1,255)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateLength(1,255)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9]+(?:-[0-9]+)+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  $context=Get-RideOfficeContext
  if($context.NativeProcess -isnot [bool] -or -not $context.NativeProcess -or $context.UserInteractive -isnot [bool] -or -not $context.UserInteractive -or
      $context.Is64BitOperatingSystem -isnot [bool] -or $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or
      $context.EditionId -ine $ExpectedEditionId -or $context.UserSid -ine $ExpectedUserSid -or $context.SessionId -isnot [int] -or
      $context.SessionId -ne $ExpectedSessionId -or ($context.UpdateBuildRevision -isnot [int] -and $context.UpdateBuildRevision -isnot [uint32]) -or
      $context.UpdateBuildRevision -lt 0){throw 'Office inventory target differs from expected native machine/build/edition/user/session.'}
  $started=[DateTime]::UtcNow.ToString('o')
  $views=if($context.Is64BitOperatingSystem){@('Registry64','Registry32')}else{@('Registry32')}
  $sources=@(foreach($view in $views){
    $result=[pscustomobject]@{Scope='Machine';RegistryView=$view;Status='Unavailable';RootExists=$null;Values=$null;ErrorId=$null}
    try{
      $rows=[Collections.Generic.List[object]]::new()
      Get-RideOfficeSource -RegistryView $view | ForEach-Object {
        if($rows.Count -ge 1){throw 'Office source returned multiple rows.'}
        $rows.Add((ConvertTo-RideOfficeSource $_))
      }
      if($rows.Count -ne 1){throw 'Office source returned no result.'}
      $result.RootExists=$rows[0].RootExists;$result.Values=$rows[0].Values;$result.Status='Captured'
    }catch{$result.RootExists=$null;$result.Values=$null;$result.ErrorId=$_.Exception.GetType().FullName}
    $result
  })
  $after=Get-RideOfficeContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','Is64BitOperatingSystem','NativeProcess','UserSid','SessionId','UserInteractive')){
    if($null -eq $after.$field -or $after.$field.GetType() -ne $context.$field.GetType() -or $after.$field -cne $context.$field){throw 'Office inventory context changed during collection; discard the observation.'}
  }
  [pscustomobject]@{
    SchemaVersion=1;Kind='OfficeClickToRunObservation';WindowsContext=$context
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o');Sources=$sources
    Consistency='Sequential machine registry metadata only; views are not merged and may be shared, reflected, stale or incomplete'
    InstalledProductsVerified=$false;EffectiveChannelVerified=$false;ActivationStatus='NotObserved';ReadyForMutation=$false;RecoverySupported=$false
  }
}
Export-ModuleMember -Function Get-RideOfficeInventory
