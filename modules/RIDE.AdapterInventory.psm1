<#
.SYNOPSIS
  Observe explicit local network adapter identities without changing networking.
.DESCRIPTION
  Captures visible and hidden adapter metadata on an expected machine/build/edition.
  Missing identifiers stay unselectable; aliases and interface indexes are labels,
  not durable selection keys. Import and completion query no machine configuration.
  No binding, IP, firewall, category, DNS, proxy or adapter setting is changed.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; native provider
  acceptance remains pending on each target. Requires available NetAdapter module.
  File/environment inputs: Explicit expected local Windows context. No output files.
  Recovery: Observation only, not an engine snapshot or permission to mutate an adapter.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded GUID-based adapter observations and saved-data lookup.
.LINK
  ../docs/network-adapter-inventory.md
#>


$ErrorActionPreference='Stop'

function Get-RideAdapterInventoryContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  [pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;UpdateBuildRevision=$version.UBR;NativeProcess=([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)}
}

function Get-RideAdapterInventoryRows {
  NetAdapter\Get-NetAdapter -Name '*' -IncludeHidden -ErrorAction Stop
}

function ConvertTo-RideAdapterObservedText {
  param($Value,[int]$Limit=1024)
  if($null -eq $Value){return $null}
  $text=[string]$Value
  if($text.Length -gt $Limit -or $text -match '[\x00-\x1f]'){throw 'Invalid adapter observation text.'}
  $text
}

function ConvertTo-RideAdapterObservedGuid {
  param($Value)
  if($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)){return $null}
  $text=[string]$Value
  if($text -cnotmatch '^(?:[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\})$'){throw 'Invalid adapter GUID observation.'}
  $id=[guid]$text
  if($id -eq [guid]::Empty){return $null}
  $id.ToString('D')
}

function Get-RideNetworkAdapterInventory {
  <#
  .SYNOPSIS
    Observe local adapter GUIDs and literal metadata on an explicitly identified OS.
  .PARAMETER ExpectedComputerName
    Intended local machine name. No remote CIM session is accepted.
  .PARAMETER ExpectedBuild
    Exact Windows build number independently supplied for the intended target.
  .PARAMETER ExpectedEditionId
    Intended Windows EditionID. Mismatch refuses provider collection.
  .EXAMPLE
    Get-RideNetworkAdapterInventory -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Bounded schema-1 adapter observation, with provider status.
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
  $context=Get-RideAdapterInventoryContext
  if(-not $context.NativeProcess -or $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId){throw 'Adapter inventory target differs from the expected native machine/build/edition.'}
  $started=[DateTime]::UtcNow.ToString('o')
  $status='Unavailable';$errorId=$null;$observed=$null
  try {
    $rows=[Collections.Generic.List[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Get-RideAdapterInventoryRows | ForEach-Object {
      if($rows.Count -ge 512){throw 'Adapter inventory exceeds the 512-row bound.'}
      $id=ConvertTo-RideAdapterObservedGuid $_.InterfaceGuid
      if($id -and -not $seen.Add($id)){throw 'Duplicate network adapter GUID observation.'}
      $index=$_.InterfaceIndex
      if($null -ne $index -and ($index -is [bool] -or $index -is [string] -or $index -isnot [ValueType] -or $index -lt 0 -or $index -gt [uint32]::MaxValue -or [decimal]$index -ne [decimal][uint32]$index)){throw 'Invalid network interface index observation.'}
      foreach($flag in @('HardwareInterface','Virtual','ConnectorPresent')){if($null -ne $_.$flag -and $_.$flag -isnot [bool]){throw 'Invalid adapter Boolean observation.'}}
      $rows.Add([pscustomobject]@{
        InterfaceGuid=$id;IdentityStatus=$(if($id){'Identified'}else{'Unavailable'})
        Name=ConvertTo-RideAdapterObservedText $_.Name
        InterfaceDescription=ConvertTo-RideAdapterObservedText $_.InterfaceDescription
        InterfaceIndex=$index;StatusObserved=ConvertTo-RideAdapterObservedText $_.Status 128
        HardwareInterface=$_.HardwareInterface;Virtual=$_.Virtual;ConnectorPresent=$_.ConnectorPresent
        Selected=$false
      })
    }
    $observed=@($rows.ToArray());$status='Captured'
  }catch{$errorId=$_.Exception.GetType().FullName;$observed=$null}
  $after=Get-RideAdapterInventoryContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','NativeProcess')){if($after.$field -cne $context.$field){throw 'Adapter inventory target changed during collection; discard the observation.'}}
  [pscustomobject]@{
    SchemaVersion=1;Kind='NetworkAdapterObservation';WindowsContext=$context
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o')
    Status=$status;ErrorId=$errorId;Adapters=$observed
    Coverage='Local Get-NetAdapter with IncludeHidden; no network profile, binding or route enumeration'
    Consistency='Sequential metadata observation; adapters may appear, disappear or change after collection'
    ReadyForMutation=$false;RecoverySupported=$false
  }
}

function Find-RideNetworkAdapterObservation {
  <#
  .SYNOPSIS
    Find one exact GUID in a supplied saved adapter observation without live discovery.
  .PARAMETER Inventory
    Schema-1 observation or its JSON representation. Unavailable and captured-empty differ.
  .PARAMETER InterfaceGuid
    Explicit adapter GUID. Completion reads identified rows in the supplied inventory only.
  .EXAMPLE
    Find-RideNetworkAdapterObservation -Inventory $saved -InterfaceGuid '<observed-guid>'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Observed, NotObserved or Unavailable, never mutation-ready.
  .NOTES
    A saved GUID match is not proof the device is still present or safe to modify.
    Names/indexes are never accepted as replacement identity; no fallback to an active NIC.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $data=$fakeBoundParameters.Inventory
        if($data.SchemaVersion -ne 1 -or $data.Kind -cne 'NetworkAdapterObservation' -or $data.Status -cne 'Captured' -or @($data.Adapters).Count -gt 512){return}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $prefix=([string]$wordToComplete).Trim("'",'"').TrimStart('{')
        foreach($row in @($data.Adapters)){
          $id=[string]$row.InterfaceGuid
          if($row.IdentityStatus -ceq 'Identified' -and $id -match '^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -and $id -ne [guid]::Empty.ToString('D') -and $id.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($id)){
            [Management.Automation.CompletionResult]::new(("'"+$id+"'"),$id,'ParameterValue',$id)
          }
        }
      }catch{return}
    })][string]$InterfaceGuid)
  $id=ConvertTo-RideAdapterObservedGuid $InterfaceGuid
  if(-not $id){throw 'Select a nonempty observed adapter GUID.'}
  if($Inventory.SchemaVersion -ne 1 -or $Inventory.Kind -cne 'NetworkAdapterObservation' -or $Inventory.Status -cnotin @('Captured','Unavailable') -or @($Inventory.Adapters).Count -gt 512){throw 'Invalid network adapter observation schema.'}
  $match=$null;$status=$Inventory.Status
  if($Inventory.Status -ceq 'Unavailable'){
    if($null -ne $Inventory.Adapters){throw 'Unavailable adapter provider cannot contain rows.'}
  }else{
    if($null -eq $Inventory.Adapters){throw 'Captured adapter observation requires a row collection.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($row in @($Inventory.Adapters)){
      $rowId=ConvertTo-RideAdapterObservedGuid $row.InterfaceGuid
      if(($rowId -and ($row.IdentityStatus -cne 'Identified' -or -not $seen.Add($rowId))) -or (-not $rowId -and ($row.IdentityStatus -cne 'Unavailable' -or $null -ne $row.InterfaceGuid))){throw 'Invalid or duplicate saved adapter identity.'}
      if($rowId -and $rowId -eq $id){$match=$row}
    }
    $status=if($match){'Observed'}else{'NotObserved'}
  }
  [pscustomobject]@{InterfaceGuid=$id;Status=$status;Observation=$match;WindowsContext=$Inventory.WindowsContext;Coverage=$Inventory.Coverage;ReadyForMutation=$false;RecoverySupported=$false}
}

Export-ModuleMember -Function Get-RideNetworkAdapterInventory,Find-RideNetworkAdapterObservation
