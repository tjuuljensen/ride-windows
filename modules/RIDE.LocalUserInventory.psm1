<#
.SYNOPSIS
  Observe local user SIDs without changing accounts or credentials.
.DESCRIPTION
  Collects bounded local-user metadata on an expected Windows machine/build/edition.
  Names remain display metadata; selection lookup uses saved SIDs only. Import and
  completion perform no account or registry query. No membership or sign-in test.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; target/provider
  acceptance pending. Requires Microsoft.PowerShell.LocalAccounts when collecting.
  File/environment inputs: Explicit expected local context. No output files.
  Recovery: Observation only; no password, account or engine restore record.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded local-user observations and saved SID lookup.
.LINK
  ../docs/local-user-inventory.md
#>
$ErrorActionPreference='Stop'

function Get-RideLocalUserInventoryContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  [pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;UpdateBuildRevision=$version.UBR;NativeProcess=([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)}
}

function Get-RideLocalUserInventoryRows {
  Microsoft.PowerShell.LocalAccounts\Get-LocalUser -ErrorAction Stop
}

function ConvertTo-RideLocalUserObservedText {
  param($Value,[int]$Limit=512)
  if($null -eq $Value){return $null}
  $text=[string]$Value
  if($text.Length -gt $Limit -or $text -match '[\x00-\x1f]'){throw 'Invalid local user observation text.'}
  $text
}

function ConvertTo-RideLocalUserObservedSid {
  param($Value)
  if($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)){return $null}
  $text=[string]$Value
  if($text -inotmatch '^S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}$'){throw 'Expected a local account SID, not a name or group identifier.'}
  foreach($part in $text.Split('-')[4..7]){if([uint64]$part -gt [uint32]::MaxValue){throw 'Local account SID subauthority exceeds UInt32.'}}
  $sid=[Security.Principal.SecurityIdentifier]::new($text)
  $sid.Value
}

function Get-RideLocalUserInventory {
  <#
  .SYNOPSIS
    Observe local users on an explicitly identified Windows target.
  .PARAMETER ExpectedComputerName
    Intended local machine name; no remote account collection.
  .PARAMETER ExpectedBuild
    Exact Windows build independently supplied for the target.
  .PARAMETER ExpectedEditionId
    Intended Windows EditionID. A mismatch refuses provider collection.
  .EXAMPLE
    Get-RideLocalUserInventory -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 local-user observation with provider status.
  .NOTES
    At most 1024 rows; no hard timeout for provider duration. No elevation prompt.
    Unavailable provider is distinct from a completed empty collection.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId
  )
  $context=Get-RideLocalUserInventoryContext
  if(-not $context.NativeProcess -or $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId){throw 'Local user inventory target differs from the expected native machine/build/edition.'}
  $started=[DateTime]::UtcNow.ToString('o')
  $status='Unavailable';$errorId=$null;$observed=$null
  try {
    $rows=[Collections.Generic.List[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Get-RideLocalUserInventoryRows | ForEach-Object {
      if($rows.Count -ge 1024){throw 'Local user inventory exceeds the 1024-row bound.'}
      $id=ConvertTo-RideLocalUserObservedSid $_.SID
      if($id -and -not $seen.Add($id)){throw 'Duplicate local user SID observation.'}
      $enabled=$_.Enabled
      if($null -ne $enabled -and $enabled -isnot [bool]){throw 'Invalid local user Enabled observation.'}
      $rows.Add([pscustomobject]@{
        Sid=$id;IdentityStatus=$(if($id){'Identified'}else{'Unavailable'})
        Name=ConvertTo-RideLocalUserObservedText $_.Name
        Enabled=$enabled;PrincipalSource=ConvertTo-RideLocalUserObservedText $_.PrincipalSource 128
        Selected=$false
      })
    }
    $observed=@($rows.ToArray());$status='Captured'
  }catch{$errorId=$_.Exception.GetType().FullName;$observed=$null}
  $after=Get-RideLocalUserInventoryContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','NativeProcess')){if($after.$field -cne $context.$field){throw 'Local user inventory target changed during collection; discard the observation.'}}
  [pscustomobject]@{
    SchemaVersion=1;Kind='LocalUserObservation';WindowsContext=$context
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o')
    Status=$status;ErrorId=$errorId;Users=$observed
    Coverage='LocalAccounts Get-LocalUser only; no group membership, directory enumeration, credentials, sign-in viability or profile ownership'
    Consistency='Sequential observation; accounts can be renamed, disabled, removed or recreated after collection'
    ReadyForMutation=$false;RecoverySupported=$false
  }
}

function Find-RideLocalUserObservation {
  <#
  .SYNOPSIS
    Find one exact SID in saved local-user observations without live account discovery.
  .PARAMETER Inventory
    Schema-1 observation or its JSON representation. Captured-empty and unavailable differ.
  .PARAMETER Sid
    Explicit observed account SID. Completion uses identified saved rows only.
  .EXAMPLE
    Find-RideLocalUserObservation -Inventory $saved -Sid 'S-1-5-21-111-222-333-1001'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Observed, NotObserved or Unavailable; never mutation-ready.
  .NOTES
    An enabled account or familiar name does not prove administrator access, ownership
    or usable credentials. A recreated account has a distinct SID; no name fallback.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $data=$fakeBoundParameters.Inventory
        if($data.SchemaVersion -ne 1 -or $data.Kind -cne 'LocalUserObservation' -or $data.Status -cne 'Captured' -or @($data.Users).Count -gt 1024){return}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $prefix=([string]$wordToComplete).Trim("'",'"')
        foreach($row in @($data.Users)){
          if($row.IdentityStatus -cne 'Identified'){continue}
          $text=[string]$row.Sid
          if($text -inotmatch '^S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}$'){continue}
          if(@($text.Split('-')[4..7]|Where-Object {[uint64]$_ -gt [uint32]::MaxValue}).Count){continue}
          try{$id=([Security.Principal.SecurityIdentifier]::new($text)).Value}catch{continue}
          if($id -and $id.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($id)){
            [Management.Automation.CompletionResult]::new(("'"+$id+"'"),$id,'ParameterValue',$id)
          }
        }
      }catch{return}
    })][string]$Sid)
  $id=ConvertTo-RideLocalUserObservedSid $Sid
  if(-not $id){throw 'Select a nonempty observed local user SID.'}
  if($Inventory.SchemaVersion -ne 1 -or $Inventory.Kind -cne 'LocalUserObservation' -or $Inventory.Status -cnotin @('Captured','Unavailable') -or @($Inventory.Users).Count -gt 1024){throw 'Invalid local user observation schema.'}
  $match=$null;$status=$Inventory.Status
  if($Inventory.Status -ceq 'Unavailable'){
    if($null -ne $Inventory.Users){throw 'Unavailable local user provider cannot contain rows.'}
  }else{
    if($null -eq $Inventory.Users){throw 'Captured local user observation requires a row collection.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($row in @($Inventory.Users)){
      $rowId=ConvertTo-RideLocalUserObservedSid $row.Sid
      if(($rowId -and ($row.IdentityStatus -cne 'Identified' -or -not $seen.Add($rowId))) -or (-not $rowId -and ($row.IdentityStatus -cne 'Unavailable' -or $null -ne $row.Sid))){throw 'Invalid or duplicate saved local user identity.'}
      if($rowId -and $rowId -eq $id){$match=$row}
    }
    $status=if($match){'Observed'}else{'NotObserved'}
  }
  [pscustomobject]@{Sid=$id;Status=$status;Observation=$match;WindowsContext=$Inventory.WindowsContext;Coverage=$Inventory.Coverage;ReadyForMutation=$false;RecoverySupported=$false}
}

Export-ModuleMember -Function Get-RideLocalUserInventory,Find-RideLocalUserObservation
