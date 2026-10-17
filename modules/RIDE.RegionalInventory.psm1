<#
.SYNOPSIS
  Observe explicitly selected regional providers without changing Windows settings.
.DESCRIPTION
  Keeps process culture, user home location, machine system locale and time zone
  separate. Captures bounded literal metadata under an expected native interactive
  machine/build/edition/user/session identity. No language or default-user copy.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; native
  provider acceptance remains pending. International and standard PowerShell modules.
  File/environment inputs: Explicit expected identity; current provider metadata.
  Recovery: Read-only observations, not complete regional recovery snapshots.
  Version: 0.1.0.
  Changelog: 0.1.0: Add four separate bounded regional observations.
.LINK
  ../docs/user-language-inventory.md
#>
$ErrorActionPreference='Stop'

function Get-RideRegionalContext {
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

function Get-RideRegionalRows {
  param([string]$Kind)
  switch($Kind){
    FormatCulture { Microsoft.PowerShell.Utility\Get-Culture -ErrorAction Stop }
    HomeLocation { International\Get-WinHomeLocation -ErrorAction Stop }
    SystemLocale { International\Get-WinSystemLocale -ErrorAction Stop }
    TimeZone { Microsoft.PowerShell.Management\Get-TimeZone -ErrorAction Stop }
    default { throw 'Unknown regional provider.' }
  }
}

function ConvertTo-RideRegionalText {
  param($Value,[int]$Maximum=256,[switch]$AllowEmpty)
  if($Value -isnot [string] -or $Value.Length -gt $Maximum -or $Value -match '[\x00-\x1f]' -or
      (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($Value))){throw 'Invalid or excessive regional text.'}
  $Value
}

function ConvertTo-RideRegionalInteger {
  param($Value,[long]$Minimum=0,[long]$Maximum=[uint32]::MaxValue)
  if(($Value -isnot [int] -and $Value -isnot [long] -and $Value -isnot [uint32]) -or
      $Value -lt $Minimum -or $Value -gt $Maximum){throw 'Invalid regional integer.'}
  [long]$Value
}

function ConvertTo-RideRegionalRow {
  param([string]$Kind,$Row)
  if($null -eq $Row){throw 'Missing regional row.'}
  switch($Kind){
    {$_ -in @('FormatCulture','SystemLocale')} {
      $name=ConvertTo-RideRegionalText $Row.Name -Maximum 128 -AllowEmpty
      if($name -cnotmatch '^[a-zA-Z0-9_-]*$'){throw 'Invalid observed culture name.'}
      $lcid=ConvertTo-RideRegionalInteger $Row.LCID
      $data=[ordered]@{Name=$name;LCID=$lcid;IsInvariantName=($name.Length -eq 0)}
      if($Kind -ceq 'FormatCulture'){
        if($Row.IsNeutralCulture -isnot [bool] -or $Row.UseUserOverride -isnot [bool]){throw 'Missing culture flags.'}
        $data.IsNeutralCulture=$Row.IsNeutralCulture;$data.UseUserOverride=$Row.UseUserOverride
        $data.NumberDecimalSeparator=ConvertTo-RideRegionalText $Row.NumberFormat.NumberDecimalSeparator -Maximum 32 -AllowEmpty
        $data.NumberGroupSeparator=ConvertTo-RideRegionalText $Row.NumberFormat.NumberGroupSeparator -Maximum 32 -AllowEmpty
        $data.CurrencySymbol=ConvertTo-RideRegionalText $Row.NumberFormat.CurrencySymbol -Maximum 64 -AllowEmpty
        $data.ShortDatePattern=ConvertTo-RideRegionalText $Row.DateTimeFormat.ShortDatePattern -Maximum 512 -AllowEmpty
        $data.ShortTimePattern=ConvertTo-RideRegionalText $Row.DateTimeFormat.ShortTimePattern -Maximum 512 -AllowEmpty
        $data.ListSeparator=ConvertTo-RideRegionalText $Row.TextInfo.ListSeparator -Maximum 32 -AllowEmpty
      }
      return [pscustomobject]$data
    }
    HomeLocation {
      return [pscustomobject]@{
        GeoId=ConvertTo-RideRegionalInteger $Row.GeoId -Minimum ([int]::MinValue) -Maximum ([int]::MaxValue)
        HomeLocation=ConvertTo-RideRegionalText $Row.HomeLocation -Maximum 256 -AllowEmpty
      }
    }
    TimeZone {
      if($Row.SupportsDaylightSavingTime -isnot [bool]){throw 'Missing time-zone daylight-support flag.'}
      return [pscustomobject]@{
        Id=ConvertTo-RideRegionalText $Row.Id -Maximum 256
        BaseUtcOffsetTicks=ConvertTo-RideRegionalInteger $Row.BaseUtcOffset.Ticks -Minimum (-14L*60*60*10000000) -Maximum (14L*60*60*10000000)
        SupportsDaylightSavingTime=$Row.SupportsDaylightSavingTime
      }
    }
  }
  throw 'Unknown regional provider.'
}

function Get-RideRegionalInventory {
  <#
  .SYNOPSIS
    Collect explicit regional observations under a verified expected execution identity.
  .PARAMETER Kind
    FormatCulture, HomeLocation, SystemLocale and/or TimeZone. No default selection.
  .PARAMETER ExpectedComputerName
    Independently supplied local machine name.
  .PARAMETER ExpectedBuild
    Expected Windows build number.
  .PARAMETER ExpectedEditionId
    Expected Windows EditionID.
  .PARAMETER ExpectedUserSid
    Intended interactive execution account SID, including for machine observations.
  .PARAMETER ExpectedSessionId
    Intended nonzero process session ID.
  .EXAMPLE
    Get-RideRegionalInventory -Kind FormatCulture,HomeLocation -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 RegionalObservation with separate provider statuses.
  .NOTES
    One row per selected provider. Missing/malformed/partial output is Unavailable.
    FormatCulture reflects the observing process; a prior Set-Culture change can
    require a new session. Time-zone metadata omits dynamic DST configuration and
    rules. System locale does not capture the UTF-8 compatibility option. No
    provider result constitutes a complete backup or proves current GUI effects.
    Collection has no hard provider timeout and does not establish atomic state.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('FormatCulture','HomeLocation','SystemLocale','TimeZone')][string[]]$Kind,
    [Parameter(Mandatory)][ValidateLength(1,255)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateLength(1,255)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9]+(?:-[0-9]+)+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  if(-not $Kind.Count){throw 'Select at least one regional provider.'}
  $selected=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($item in $Kind){if(-not $selected.Add($item)){throw 'Select each regional provider only once.'}}
  $context=Get-RideRegionalContext
  if($context.NativeProcess -isnot [bool] -or -not $context.NativeProcess -or $context.UserInteractive -isnot [bool] -or -not $context.UserInteractive -or
      $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId -or
      $context.UserSid -ine $ExpectedUserSid -or $context.SessionId -ne $ExpectedSessionId){throw 'Regional inventory target differs from the expected native machine/build/edition/user/session.'}
  $null=ConvertTo-RideRegionalInteger $context.UpdateBuildRevision
  $null=ConvertTo-RideRegionalInteger $context.SessionId -Minimum 1 -Maximum ([int]::MaxValue)
  $started=[DateTime]::UtcNow.ToString('o')
  $providers=@(foreach($item in $Kind){
    $canonical=switch($item){FormatCulture{'FormatCulture'}HomeLocation{'HomeLocation'}SystemLocale{'SystemLocale'}TimeZone{'TimeZone'}}
    $scope=if($canonical -in @('FormatCulture','HomeLocation')){'User'}else{'Machine'}
    $result=[pscustomobject]@{Kind=$canonical;Scope=$scope;Status='Unavailable';Value=$null;ErrorId=$null;EffectiveValueVerified=$false}
    try {
      $rows=[Collections.Generic.List[object]]::new()
      Get-RideRegionalRows -Kind $canonical | ForEach-Object {
        if($rows.Count -ge 1){throw 'Regional provider returned multiple rows.'}
        $rows.Add((ConvertTo-RideRegionalRow -Kind $canonical -Row $_))
      }
      if($rows.Count -ne 1){throw 'Regional provider returned no value.'}
      $result.Value=$rows[0];$result.Status='Captured'
    }catch{$result.Value=$null;$result.ErrorId=$_.Exception.GetType().FullName}
    $result
  })
  $after=Get-RideRegionalContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','NativeProcess','UserSid','SessionId','UserInteractive')){
    if($after.$field -cne $context.$field){throw 'Regional inventory target changed during collection; discard the observation.'}
  }
  [pscustomobject]@{
    SchemaVersion=1;Kind='RegionalObservation';WindowsContext=$context
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o');Providers=$providers
    Coverage='Selected process format-culture metadata, user GeoID, machine system-locale identity and time-zone metadata'
    Consistency='Sequential observations; process culture can be stale; no full custom-format, UTF-8 mode, dynamic DST/rules, UI, installed-language or managed-policy proof'
    ReadyForMutation=$false;RecoverySupported=$false
  }
}

Export-ModuleMember -Function Get-RideRegionalInventory
