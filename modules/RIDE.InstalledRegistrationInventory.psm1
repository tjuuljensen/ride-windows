<#
.SYNOPSIS
  Observe uninstall registration identities without executing package providers.
.DESCRIPTION
  Reads explicitly selected machine/current-user uninstall roots through explicit
  registry views. Retains every registration with bounded literal metadata and
  separate source status. Does not query Win32_Product, run commands or infer ownership.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Native registry-view and intended-user acceptance remain pending.
  File/environment inputs: Expected machine/build/edition/user/session; registry reads.
  Recovery: Read-only observation, not an adoption or pre-installation backup.
  Version: 0.2.0.
  Changelog: 0.2.0: Validate and copy supplied observations for offline review.
    0.1.0: Add bounded per-view uninstall registration inventory.
.LINK
  ../docs/application-packages.md
#>
$ErrorActionPreference='Stop'
$script:RegistrationRoot='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$script:RegistrationFields=@('DisplayName','DisplayVersion','Publisher','InstallLocation','WindowsInstaller','SystemComponent')

function Get-RideInstalledRegistrationContext {
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

function Open-RideInstalledRegistrationBaseKey {
  param([string]$Scope,[string]$RegistryView)
  $hive=if($Scope -ceq 'Machine'){[Microsoft.Win32.RegistryHive]::LocalMachine}else{[Microsoft.Win32.RegistryHive]::CurrentUser}
  [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,[Microsoft.Win32.RegistryView]$RegistryView)
}

function Get-RideInstalledRegistrationSource {
  param([string]$Scope,[string]$RegistryView)
  $base=$null;$root=$null
  try{
    $base=Open-RideInstalledRegistrationBaseKey -Scope $Scope -RegistryView $RegistryView
    $root=$base.OpenSubKey($script:RegistrationRoot,$false)
    if($null -eq $root){return [pscustomobject]@{RootExists=$false;Entries=@()}}
    $names=@($root.GetSubKeyNames())
    if($names.Count -gt 2048){throw 'Uninstall source exceeds 2048 registrations.'}
    $entries=[Collections.Generic.List[object]]::new()
    foreach($name in $names){
      $key=$null
      try{
        $key=$root.OpenSubKey($name,$false)
        if($null -eq $key){throw 'Uninstall registration disappeared during observation.'}
        $present=@($key.GetValueNames());$values=[ordered]@{}
        foreach($field in $script:RegistrationFields){
          $exists=$present -icontains $field
          $kind=$null;$value=$null
          if($exists){$kind=$key.GetValueKind($field).ToString();$value=$key.GetValue($field,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
          $values[$field]=[pscustomobject]@{Exists=$exists;Kind=$kind;Value=$value}
        }
        $entries.Add([pscustomobject]@{KeyName=$name;Values=[pscustomobject]$values})
      }finally{if($null -ne $key){$key.Dispose()}}
    }
    [pscustomobject]@{RootExists=$true;Entries=@($entries.ToArray())}
  }finally{
    try{if($null -ne $root){$root.Dispose()}}finally{if($null -ne $base){$base.Dispose()}}
  }
}

function ConvertTo-RideInstalledRegistrationEntry {
  param($Entry)
  if($Entry.KeyName -isnot [string] -or [string]::IsNullOrWhiteSpace($Entry.KeyName) -or $Entry.KeyName.Length -gt 255 -or $Entry.KeyName -match '[\\\x00-\x1f]'){throw 'Invalid uninstall registration key identity.'}
  $values=[ordered]@{}
  foreach($field in $script:RegistrationFields){
    $saved=$Entry.Values.$field
    if($saved.Exists -isnot [bool]){throw 'Missing literal uninstall value presence.'}
    $value=$null;$kind=$null
    if(-not $saved.Exists){
      if($null -ne $saved.Kind -or $null -ne $saved.Value){throw 'Absent uninstall value must have null kind/data.'}
    }else{
      $kind=$saved.Kind
      if($field -in @('WindowsInstaller','SystemComponent')){
        if($kind -cne 'DWord' -or ($saved.Value -isnot [int] -and $saved.Value -isnot [long] -and $saved.Value -isnot [uint32])){throw 'Invalid uninstall numeric metadata.'}
        $value=[long]$saved.Value
        if($saved.Value -is [int] -and $value -lt 0){$value+=4294967296L}
        if($value -lt 0 -or $value -gt [uint32]::MaxValue){throw 'Uninstall DWord metadata exceeds UInt32.'}
      }else{
        if($kind -cnotin @('String','ExpandString') -or $saved.Value -isnot [string] -or $saved.Value.Length -gt 4096 -or $saved.Value -match '[\x00-\x1f]'){throw 'Invalid or excessive uninstall string metadata.'}
        $value=$saved.Value
      }
    }
    $values[$field]=[pscustomobject]@{Exists=$saved.Exists;Kind=$kind;Value=$value}
  }
  [pscustomobject]@{KeyName=$Entry.KeyName;Values=[pscustomobject]$values;IdentityStatus='RegistrationObserved';InstalledStateVerified=$false;OwnershipVerified=$false}
}

function Get-RideInstalledRegistrationInventory {
  <#
  .SYNOPSIS
    Capture selected uninstall roots under an explicit expected execution identity.
  .PARAMETER Scope
    Machine and/or current User; each scope exactly once. Views are explicit in output.
  .PARAMETER ExpectedComputerName
    Independently supplied local computer name.
  .PARAMETER ExpectedBuild
    Expected Windows build number.
  .PARAMETER ExpectedEditionId
    Expected Windows EditionID.
  .PARAMETER ExpectedUserSid
    Intended interactive execution account, also when observing machine registrations.
  .PARAMETER ExpectedSessionId
    Intended nonzero interactive process session.
  .EXAMPLE
    Get-RideInstalledRegistrationInventory -Scope Machine,User -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 InstalledRegistrationObservation with per-source statuses.
  .NOTES
    Up to 2048 registrations per view. Reads Registry64 and Registry32 on 64-bit
    Windows; Registry32 only on 32-bit Windows. Shared/reflected entries are not
    silently merged. Read failures discard the affected source's partial data.
    Missing roots are captured empty sources, not errors. Collection is sequential,
    not atomic, and has no hard provider timeout. No uninstall commands are collected.
    A registration may be stale, incomplete or unrelated to an installed application;
    display names, publisher and location do not prove package identity or ownership.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Machine','User')][string[]]$Scope,
    [Parameter(Mandatory)][ValidateLength(1,255)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateLength(1,255)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9]+(?:-[0-9]+)+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  if(-not $Scope.Count){throw 'Select an explicit registration scope.'}
  $selected=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($item in $Scope){if(-not $selected.Add($item)){throw 'Select each registration scope only once.'}}
  $context=Get-RideInstalledRegistrationContext
  if($context.NativeProcess -isnot [bool] -or -not $context.NativeProcess -or $context.UserInteractive -isnot [bool] -or -not $context.UserInteractive -or $context.Is64BitOperatingSystem -isnot [bool] -or
      $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId -or $context.UserSid -ine $ExpectedUserSid -or $context.SessionId -ne $ExpectedSessionId){throw 'Registration inventory target differs from the expected native machine/build/edition/user/session.'}
  if(($context.UpdateBuildRevision -isnot [int] -and $context.UpdateBuildRevision -isnot [long] -and $context.UpdateBuildRevision -isnot [uint32]) -or $context.UpdateBuildRevision -lt 0 -or $context.UpdateBuildRevision -gt [uint32]::MaxValue -or ($context.SessionId -isnot [int] -and $context.SessionId -isnot [long])){throw 'Invalid registration inventory context revision/session.'}
  $started=[DateTime]::UtcNow.ToString('o')
  $views=if($context.Is64BitOperatingSystem){@('Registry64','Registry32')}else{@('Registry32')}
  $sources=@(foreach($item in $Scope){
    $canonical=if($item -ieq 'Machine'){'Machine'}else{'User'}
    foreach($view in $views){
      $result=[pscustomobject]@{Scope=$canonical;RegistryView=$view;RegistryPath=$script:RegistrationRoot;RootExists=$null;Status='Unavailable';Entries=@();ErrorId=$null}
      try{
        $output=@(Get-RideInstalledRegistrationSource -Scope $canonical -RegistryView $view)
        if($output.Count -ne 1 -or $output[0].RootExists -isnot [bool] -or $null -eq $output[0].Entries -or $output[0].Entries -is [string] -or $output[0].Entries -isnot [Collections.IEnumerable]){throw 'Invalid or incomplete uninstall source observation.'}
        $rows=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($entry in $output[0].Entries){
          if($rows.Count -ge 2048){throw 'Uninstall source exceeds 2048 registrations.'}
          $row=ConvertTo-RideInstalledRegistrationEntry $entry
          if(-not $seen.Add($row.KeyName)){throw 'Duplicate uninstall registration identity in one view.'}
          $rows.Add($row)
        }
        if(-not $output[0].RootExists -and $rows.Count){throw 'Missing uninstall root cannot contain registrations.'}
        $result.RootExists=$output[0].RootExists;$result.Entries=@($rows.ToArray());$result.Status='Captured'
      }catch{$result.RootExists=$null;$result.Entries=@();$result.ErrorId=$_.Exception.GetType().FullName}
      $result
    }
  })
  $after=Get-RideInstalledRegistrationContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','Is64BitOperatingSystem','NativeProcess','UserSid','SessionId','UserInteractive')){
    if($after.$field -cne $context.$field){throw 'Registration inventory target changed during collection; discard the observation.'}
  }
  [pscustomobject]@{
    SchemaVersion=1;Kind='InstalledRegistrationObservation';WindowsContext=$context;Sources=$sources
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o')
    Coverage='Explicit local machine/current-user uninstall registry views only; no other users, MSI provider, Store, portable tree, service or executable inspection'
    Consistency='Sequential observations; no installed-product authentication, live ownership, adoption, replacement, recovery or complete system inventory'
    ReadyForMutation=$false;RecoverySupported=$false
  }
}

function Get-RideInstalledRegistrationReviewData {
  <#
  .SYNOPSIS
    Validate and copy supplied registration observations without querying Windows.
  .PARAMETER Inventory
    Schema-1 InstalledRegistrationObservation, including context and source statuses.
  .EXAMPLE
    Get-RideInstalledRegistrationReviewData -Inventory $savedObservation
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Validated context/sources for review, with ReadyForMutation=false.
  .NOTES
    This verifies structural consistency only, not authenticity, freshness, completeness
    or current machine identity. Missing views remain missing for the review consumer
    to report. No source status is promoted and no registration is merged.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory)
  if(($Inventory.SchemaVersion -isnot [int] -and $Inventory.SchemaVersion -isnot [long]) -or $Inventory.SchemaVersion -ne 1 -or
      $Inventory.Kind -cne 'InstalledRegistrationObservation' -or $Inventory.ReadyForMutation -isnot [bool] -or $Inventory.ReadyForMutation -or
      $Inventory.RecoverySupported -isnot [bool] -or $Inventory.RecoverySupported){throw 'Expected a schema-1 read-only installed registration observation.'}
  $context=$Inventory.WindowsContext;$copy=[ordered]@{}
  foreach($field in @('ComputerName','Build','EditionId','UserSid')){
    if($context.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($context.$field) -or $context.$field.Length -gt 255 -or $context.$field -match '[\x00-\x1f]'){throw 'Invalid saved registration context.'}
    $copy[$field]=$context.$field
  }
  if($context.Build -cnotmatch '^[0-9]{4,8}$' -or $context.UserSid -cnotmatch '^S-1-[0-9]+(?:-[0-9]+)+$'){throw 'Invalid saved registration build or SID.'}
  try{$sid=[Security.Principal.SecurityIdentifier]::new($context.UserSid)}catch{throw 'Invalid saved registration SID.'}
  if($sid.Value -cne $context.UserSid){throw 'Saved registration SID must be canonical.'}
  foreach($field in @('UpdateBuildRevision','SessionId')){
    if(($context.$field -isnot [int] -and $context.$field -isnot [long] -and $context.$field -isnot [uint32]) -or $context.$field -lt 0 -or $context.$field -gt [uint32]::MaxValue){throw 'Invalid saved registration numeric context.'}
    $copy[$field]=[long]$context.$field
  }
  if($context.SessionId -lt 1 -or $context.SessionId -gt [int]::MaxValue){throw 'Invalid saved interactive session.'}
  foreach($field in @('Is64BitOperatingSystem','NativeProcess','UserInteractive')){
    if($context.$field -isnot [bool]){throw 'Invalid saved registration context flag.'}
    $copy[$field]=$context.$field
  }
  if(-not $context.NativeProcess -or -not $context.UserInteractive){throw 'Saved registration observation requires a native interactive context.'}
  if($null -eq $Inventory.Sources -or $Inventory.Sources -is [string] -or $Inventory.Sources -isnot [Collections.IEnumerable]){throw 'Missing registration sources.'}
  $sources=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($source in $Inventory.Sources){
    if($sources.Count -ge 4 -or $source.Scope -cnotin @('Machine','User') -or $source.RegistryView -cnotin @('Registry64','Registry32') -or
        (-not $context.Is64BitOperatingSystem -and $source.RegistryView -ceq 'Registry64') -or $source.RegistryPath -cne $script:RegistrationRoot -or
        -not $seen.Add($source.Scope+'/'+$source.RegistryView)){throw 'Invalid or duplicate saved registration source.'}
    if($null -eq $source.Entries -or $source.Entries -is [string] -or $source.Entries -isnot [Collections.IEnumerable]){throw 'Missing saved registration entries.'}
    $entries=[Collections.Generic.List[object]]::new();$keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($entry in $source.Entries){
      if($entries.Count -ge 2048){throw 'Saved registration source exceeds 2048 entries.'}
      $row=ConvertTo-RideInstalledRegistrationEntry $entry
      if(-not $keys.Add($row.KeyName)){throw 'Duplicate saved registration key.'}
      $entries.Add($row)
    }
    if($source.Status -ceq 'Captured'){
      if($source.RootExists -isnot [bool] -or (-not $source.RootExists -and $entries.Count) -or $null -ne $source.ErrorId){throw 'Inconsistent captured registration source.'}
    }elseif($source.Status -ceq 'Unavailable'){
      if($null -ne $source.RootExists -or $entries.Count){throw 'Unavailable registration source cannot contain partial records.'}
      if($source.ErrorId -isnot [string] -or $source.ErrorId.Length -gt 256 -or $source.ErrorId -cnotmatch '^[A-Za-z0-9_.+`]+$'){throw 'Invalid saved registration error type.'}
    }else{throw 'Unknown saved registration source status.'}
    $sources.Add([pscustomobject]@{Scope=$source.Scope;RegistryView=$source.RegistryView;RegistryPath=$script:RegistrationRoot;RootExists=$source.RootExists;Status=$source.Status;Entries=@($entries.ToArray());ErrorId=$source.ErrorId})
  }
  [pscustomobject]@{SchemaVersion=1;Kind='InstalledRegistrationObservation';WindowsContext=[pscustomobject]$copy;Sources=@($sources.ToArray());ReadyForMutation=$false;RecoverySupported=$false}
}

Export-ModuleMember -Function Get-RideInstalledRegistrationInventory,Get-RideInstalledRegistrationReviewData
