<#
.SYNOPSIS
  Observe explicit local volume identities without changing storage configuration.
.DESCRIPTION
  Captures local volume metadata on an expected machine/build/edition.
  Missing identifiers stay unselectable; labels and drive letters are observations,
  not selection keys. Import and completion query no machine configuration.
  No mount, format, protection, cleanup, BitLocker or volume setting is changed.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; native provider
  acceptance remains pending on each target. Requires available CIM cmdlets.
  File/environment inputs: Explicit expected local Windows context. No output files.
  Recovery: Observation only, not an engine snapshot or permission to mutate a volume.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded GUID-path volume observations and saved-data lookup.
.LINK
  ../docs/volume-inventory.md
#>


$ErrorActionPreference='Stop'

function Get-RideVolumeInventoryContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  [pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;UpdateBuildRevision=$version.UBR;NativeProcess=([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)}
}

function Get-RideVolumeInventoryRows {
  CimCmdlets\Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Volume -Property DeviceID,DriveLetter,DriveType,FileSystem,Label,SerialNumber -ErrorAction Stop
}

function ConvertTo-RideVolumeObservedText {
  param($Value,[int]$Limit=1024)
  if($null -eq $Value){return $null}
  $text=[string]$Value
  if($text.Length -gt $Limit -or $text -match '[\x00-\x1f]'){throw 'Invalid volume observation text.'}
  $text
}

function ConvertTo-RideVolumeObservedPath {
  param($Value)
  if($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)){return $null}
  $text=[string]$Value
  if($text -inotmatch '^\\\\\?\\Volume\{([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\}\\$'){throw 'Invalid volume GUID path observation.'}
  $id=[guid]$Matches[1]
  if($id -eq [guid]::Empty){return $null}
  '\\?\Volume{'+$id.ToString('D')+'}\'
}

function ConvertTo-RideVolumeObservedUInt32 {
  param($Value)
  if($null -eq $Value){return $null}
  if($Value -is [bool] -or $Value -is [string] -or $Value -isnot [ValueType] -or $Value -lt 0 -or $Value -gt [uint32]::MaxValue -or [decimal]$Value -ne [decimal][uint32]$Value){throw 'Invalid volume numeric observation.'}
  [uint32]$Value
}

function Get-RideVolumeInventory {
  <#
  .SYNOPSIS
    Observe local volume GUIDs and literal metadata on an explicitly identified OS.
  .PARAMETER ExpectedComputerName
    Intended local machine name. No remote CIM session is accepted.
  .PARAMETER ExpectedBuild
    Exact Windows build number independently supplied for the intended target.
  .PARAMETER ExpectedEditionId
    Intended Windows EditionID. Mismatch refuses provider collection.
  .EXAMPLE
    Get-RideVolumeInventory -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Bounded schema-1 volume observation, with provider status.
  .NOTES
    At most 512 rows. Provider duration is not hard-time-limited. No elevation prompt;
    access/provider errors report Unavailable rather than an empty successful inventory.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId
  )
  $context=Get-RideVolumeInventoryContext
  if(-not $context.NativeProcess -or $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId){throw 'Volume inventory target differs from the expected native machine/build/edition.'}
  $started=[DateTime]::UtcNow.ToString('o')
  $status='Unavailable';$errorId=$null;$observed=$null
  try {
    $rows=[Collections.Generic.List[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Get-RideVolumeInventoryRows | ForEach-Object {
      if($rows.Count -ge 512){throw 'Volume inventory exceeds the 512-row bound.'}
      $id=ConvertTo-RideVolumeObservedPath $_.DeviceID
      if($id -and -not $seen.Add($id)){throw 'Duplicate volume GUID observation.'}
      $letter=ConvertTo-RideVolumeObservedText $_.DriveLetter 2
      if($null -ne $letter -and $letter -notmatch '^[a-zA-Z]:$'){throw 'Invalid observed volume drive letter.'}
      $rows.Add([pscustomobject]@{
        VolumeGuidPath=$id;IdentityStatus=$(if($id){'Identified'}else{'Unavailable'})
        DriveLetter=$letter;Label=ConvertTo-RideVolumeObservedText $_.Label
        FileSystem=ConvertTo-RideVolumeObservedText $_.FileSystem 128
        DriveType=ConvertTo-RideVolumeObservedUInt32 $_.DriveType
        SerialNumber=ConvertTo-RideVolumeObservedUInt32 $_.SerialNumber
        Selected=$false
      })
    }
    $observed=@($rows.ToArray());$status='Captured'
  }catch{$errorId=$_.Exception.GetType().FullName;$observed=$null}
  $after=Get-RideVolumeInventoryContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','NativeProcess')){if($after.$field -cne $context.$field){throw 'Volume inventory target changed during collection; discard the observation.'}}
  [pscustomobject]@{
    SchemaVersion=1;Kind='VolumeObservation';WindowsContext=$context
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o')
    Status=$status;ErrorId=$errorId;Volumes=$observed
    Coverage='Local root/cimv2 Win32_Volume; no physical disk, partition, mount-folder, boot-role or protection enumeration'
    Consistency='Sequential metadata observation; volumes may appear, disappear or change after collection; multiple GUID paths can identify one volume'
    ReadyForMutation=$false;RecoverySupported=$false
  }
}

function Find-RideVolumeObservation {
  <#
  .SYNOPSIS
    Find one exact volume GUID path in a supplied saved volume observation without live discovery.
  .PARAMETER Inventory
    Schema-1 observation or its JSON representation. Unavailable and captured-empty differ.
  .PARAMETER VolumeGuidPath
    Explicit volume GUID path. Completion reads identified rows in the supplied inventory only.
  .EXAMPLE
    Find-RideVolumeObservation -Inventory $saved -VolumeGuidPath '\\?\Volume{<observed-guid>}\'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Observed, NotObserved or Unavailable, never mutation-ready.
  .NOTES
    A saved GUID match is not proof the device is still present or safe to modify.
    Drive letters/labels/serials are never replacement identities; no boot-volume fallback.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $data=$fakeBoundParameters.Inventory
        if($data.SchemaVersion -ne 1 -or $data.Kind -cne 'VolumeObservation' -or $data.Status -cne 'Captured' -or @($data.Volumes).Count -gt 512){return}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $prefix=([string]$wordToComplete).Trim("'",'"')
        foreach($row in @($data.Volumes)){
          $id=[string]$row.VolumeGuidPath
          if($row.IdentityStatus -ceq 'Identified' -and $id -imatch '^\\\\\?\\Volume\{([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\}\\$' -and [guid]$Matches[1] -ne [guid]::Empty -and $id.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($id)){
            [Management.Automation.CompletionResult]::new(("'"+$id+"'"),$id,'ParameterValue',$id)
          }
        }
      }catch{return}
    })][string]$VolumeGuidPath)
  $id=ConvertTo-RideVolumeObservedPath $VolumeGuidPath
  if(-not $id){throw 'Select a nonempty observed volume GUID path.'}
  if($Inventory.SchemaVersion -ne 1 -or $Inventory.Kind -cne 'VolumeObservation' -or $Inventory.Status -cnotin @('Captured','Unavailable') -or @($Inventory.Volumes).Count -gt 512){throw 'Invalid volume observation schema.'}
  $match=$null;$status=$Inventory.Status
  if($Inventory.Status -ceq 'Unavailable'){
    if($null -ne $Inventory.Volumes){throw 'Unavailable volume provider cannot contain rows.'}
  }else{
    if($null -eq $Inventory.Volumes){throw 'Captured volume observation requires a row collection.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($row in @($Inventory.Volumes)){
      $rowId=ConvertTo-RideVolumeObservedPath $row.VolumeGuidPath
      if(($rowId -and ($row.IdentityStatus -cne 'Identified' -or -not $seen.Add($rowId))) -or (-not $rowId -and ($row.IdentityStatus -cne 'Unavailable' -or $null -ne $row.VolumeGuidPath))){throw 'Invalid or duplicate saved volume identity.'}
      if($rowId -and $rowId -eq $id){$match=$row}
    }
    $status=if($match){'Observed'}else{'NotObserved'}
  }
  [pscustomobject]@{VolumeGuidPath=$id;Status=$status;Observation=$match;WindowsContext=$Inventory.WindowsContext;Coverage=$Inventory.Coverage;ReadyForMutation=$false;RecoverySupported=$false}
}

Export-ModuleMember -Function Get-RideVolumeInventory,Find-RideVolumeObservation
