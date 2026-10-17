<#
.SYNOPSIS
  Prepare explicit named mappings for supplied legacy package selection records.
.DESCRIPTION
  Preserves all legacy selection data in a bounded deep copy and binds a new
  explicit deployment identity without resolving current variants or destinations.
  No state-file read/write or automatic adoption, install, removal or migration.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  File/environment inputs: Supplied PackageSelections schema-1 data and expected IDs.
  Recovery: Version-1 preparation keeps the original logical record. Original file
  bytes, store ACLs, machine/user provenance and durable commit remain future work.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded legacy selection mapping and logical recovery.
.LINK
  ../docs/application-packages.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.DeploymentIdentity.psm1') -ErrorAction Stop

function Copy-RideLegacyDeploymentData {
  param($Value,[hashtable]$Budget,[int]$Depth=0)
  $Budget.Nodes++
  if($Depth -gt 32 -or $Budget.Nodes -gt 16384){throw 'Legacy selection exceeds its depth or node bound.'}
  if($null -eq $Value){return $null}
  if($Value -is [string]){
    $Budget.Characters+=$Value.Length
    if($Value.Length -gt 65536 -or $Budget.Characters -gt 1048576){throw 'Legacy selection exceeds its string bound.'}
    return $Value
  }
  if($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [decimal]){return $Value}
  if($Value -is [double] -or $Value -is [single]){
    if([double]::IsNaN([double]$Value) -or [double]::IsInfinity([double]$Value)){throw 'Non-finite legacy numeric value.'}
    return $Value
  }
  if($Value -is [Collections.IDictionary]){
    $copy=[ordered]@{};$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($key in $Value.Keys){
      if($key -isnot [string] -or -not $key.Length -or $key.Length -gt 256 -or $key -match '[\x00-\x1f]' -or -not $seen.Add($key)){throw 'Invalid or duplicate legacy data property.'}
      $copy[$key]=Copy-RideLegacyDeploymentData -Value $Value[$key] -Budget $Budget -Depth ($Depth+1)
    }
    return $copy
  }
  if($Value -is [System.Management.Automation.PSCustomObject]){
    $copy=[ordered]@{};$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($property in $Value.PSObject.Properties){
      if($property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or -not $property.Name.Length -or $property.Name.Length -gt 256 -or $property.Name -match '[\x00-\x1f]' -or -not $seen.Add($property.Name)){throw 'Legacy input must contain literal data properties only.'}
      $copy[$property.Name]=Copy-RideLegacyDeploymentData -Value $property.Value -Budget $Budget -Depth ($Depth+1)
    }
    return [pscustomobject]$copy
  }
  if($Value -is [Array] -or $Value -is [Collections.IList]){
    $items=[Collections.Generic.List[object]]::new()
    foreach($item in $Value){$items.Add((Copy-RideLegacyDeploymentData -Value $item -Budget $Budget -Depth ($Depth+1)))}
    return ,@($items.ToArray())
  }
  throw 'Unsupported non-data value in legacy selection; preserve the original source without conversion.'
}

function Get-RideLegacySelectionCopy {
  param($Selection)
  $copy=Copy-RideLegacyDeploymentData -Value $Selection -Budget @{Nodes=0;Characters=0}
  if(($copy.SchemaVersion -isnot [int] -and $copy.SchemaVersion -isnot [long]) -or $copy.SchemaVersion -ne 1 -or
      $copy.Operation.Kind -cne 'Package' -or -not $copy.Operation.SelectedVariant -or $copy.Operation.Variants){throw 'Expected a resolved PackageSelections schema-1 record.'}
  $copy
}

function New-RideLegacyDeploymentMapping {
  <#
  .SYNOPSIS
    Associate supplied legacy selection data with an explicitly named deployment.
  .PARAMETER Selection
    Supplied existing PackageSelections schema-1 record, not a run snapshot.
  .PARAMETER DeploymentId
    Explicit new lowercase deployment name. No default name is invented.
  .PARAMETER ExpectedOperation
    Trusted base catalog operation used only to compare stable Id, PackageId and
    optional Library.Id. Current defaults/variants/paths do not replace saved data.
  .PARAMETER ExpectedScope
    Explicit expected store scope, Machine or User.
  .PARAMETER UserSid
    Explicit intended-user SID for a User store; omit for Machine. The old record
    itself does not authenticate store owner or executing user.
  .EXAMPLE
    New-RideLegacyDeploymentMapping -Selection $old -DeploymentId sharex-workstation -ExpectedOperation $catalogPackage -ExpectedScope Machine
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Version-1 LegacyPackageDeploymentMapping preparation.
  .NOTES
    Does not read JSON, create an index or enable coexistence. Unknown literal
    fields and retired saved variants remain retained. A future durable adapter
    must preserve original bytes, reject ambiguous parsing, bind store provenance,
    reserve unique names and journal commit/recovery before changing existing state.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Selection,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DeploymentId,
    [Parameter(Mandatory)]$ExpectedOperation,
    [Parameter(Mandatory)][ValidateSet('Machine','User')][string]$ExpectedScope,
    [string]$UserSid)
  $copy=Get-RideLegacySelectionCopy $Selection
  $op=$copy.Operation
  $library=if($null -ne $op.Library){$op.Library.Id}else{''}
  $expectedLibrary=if($null -ne $ExpectedOperation.Library){$ExpectedOperation.Library.Id}else{''}
  if($ExpectedOperation.Kind -cne 'Package' -or $op.Id -cne $ExpectedOperation.Id -or $op.PackageId -cne $ExpectedOperation.PackageId -or
      $library -cne $expectedLibrary -or $op.Scope -ine $ExpectedScope){throw 'Legacy selection does not match the expected product/library/store identity.'}
  $identityArgs=@{Operation=$op;DeploymentId=$DeploymentId}
  if($PSBoundParameters.ContainsKey('UserSid')){$identityArgs.UserSid=$UserSid}
  $identity=New-RidePackageDeploymentIdentity @identityArgs
  [pscustomobject]@{
    SchemaVersion=1;Kind='LegacyPackageDeploymentMapping';SourceFormat='PackageSelections/v1'
    Identity=$identity;OriginalSelection=$copy;ReadyForMigration=$false;OriginalFileBytesPreserved=$false
    Limitation='Logical data mapping only; no authenticated store provenance, original-byte archive, unique-name reservation, durable migration or activation'
  }
}

function Get-RideLegacyDeploymentSelection {
  <#
  .SYNOPSIS
    Recover a copied logical legacy selection from a consistent prepared mapping.
  .PARAMETER Mapping
    Version-1 LegacyPackageDeploymentMapping produced by the preparation API.
  .EXAMPLE
    Get-RideLegacyDeploymentSelection -Mapping $prepared
  .INPUTS
    None.
  .OUTPUTS
    Object. Deep copy of the original PackageSelections schema-1 logical record.
  .NOTES
    Verifies identity consistency, not authenticity. It does not restore a state file
    or replace an existing index. Unknown preserved data remains inert and must not
    be passed directly to a handler without the existing engine's recovery guards.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Mapping)
  if(($Mapping.SchemaVersion -isnot [int] -and $Mapping.SchemaVersion -isnot [long]) -or $Mapping.SchemaVersion -ne 1 -or $Mapping.Kind -cne 'LegacyPackageDeploymentMapping' -or
      $Mapping.SourceFormat -cne 'PackageSelections/v1' -or $Mapping.ReadyForMigration -isnot [bool] -or $Mapping.ReadyForMigration -or
      $Mapping.OriginalFileBytesPreserved -isnot [bool] -or $Mapping.OriginalFileBytesPreserved){throw 'Invalid legacy deployment preparation schema.'}
  $identities=@(Get-RidePackageDeploymentIdentity -Records @($Mapping.Identity))
  $identity=$identities[0];$copy=Get-RideLegacySelectionCopy $Mapping.OriginalSelection
  $args=@{Operation=$copy.Operation;DeploymentId=$identity.DeploymentId}
  if($identity.Scope -ceq 'User'){$args.UserSid=$identity.UserSid}
  $reconstructed=New-RidePackageDeploymentIdentity @args
  foreach($field in @('OperationId','PackageId','Variant','LibraryId','Scope','UserSid')){
    if($reconstructed.$field -cne $identity.$field){throw 'Prepared identity disagrees with the preserved legacy selection.'}
  }
  $copy
}

Export-ModuleMember -Function New-RideLegacyDeploymentMapping,Get-RideLegacyDeploymentSelection
