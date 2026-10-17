<#
.SYNOPSIS
  Prepare and select named package identities from supplied metadata.
.DESCRIPTION
  Implements explicit deployment selection independently from paths, installation,
  ownership and kit membership. Uses no engine, state store or native discovery.
  These schema-1 identities are preparation data, not installation/recovery records.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  File/environment inputs: Supplied resolved package metadata and identity collection.
  Recovery: No mutation. Existing selection indexes and saved runs remain unchanged.
  Version: 0.1.0.
  Changelog: 0.1.0: Add named identity preparation, inspection and ambiguity refusal.
.LINK
  ../docs/application-packages.md
#>
$ErrorActionPreference='Stop'

function Test-RideDeploymentText {
  param($Value,[string]$Pattern,[int]$Maximum=128)
  $Value -is [string] -and $Value.Length -le $Maximum -and $Value -cmatch $Pattern
}

function ConvertTo-RideDeploymentIdentity {
  param($Record)
  if($null -eq $Record -or ($Record.SchemaVersion -isnot [int] -and $Record.SchemaVersion -isnot [long]) -or
      $Record.SchemaVersion -ne 1 -or $Record.Kind -cne 'PackageDeploymentIdentity' -or
      $Record.ReadyForMutation -isnot [bool] -or $Record.ReadyForMutation){throw 'Expected a schema-1 package deployment preparation identity.'}
  if(-not (Test-RideDeploymentText $Record.DeploymentId '^[a-z][a-z0-9-]*$' 64) -or
      $Record.DeploymentId -match '^(con|prn|aux|nul|com[1-9]|lpt[1-9])$'){throw 'Deployment ID must be a non-reserved lowercase name of at most 64 characters.'}
  if(-not (Test-RideDeploymentText $Record.OperationId '^[a-z][a-z0-9.-]+$') -or
      -not (Test-RideDeploymentText $Record.PackageId '^[A-Za-z0-9][A-Za-z0-9._-]*$') -or
      -not (Test-RideDeploymentText $Record.Variant '^[a-z][a-z0-9-]*$')){throw 'Invalid deployment operation, product or variant identity.'}
  if($Record.LibraryId -isnot [string] -or ($Record.LibraryId.Length -gt 0 -and -not (Test-RideDeploymentText $Record.LibraryId '^[a-z][a-z0-9.-]*$'))){throw 'LibraryId must be an explicit empty built-in identity or a stable library ID.'}
  if($Record.Scope -cnotin @('Machine','User')){throw 'Deployment scope must be Machine or User.'}
  if($Record.Scope -ceq 'User'){
    if(-not (Test-RideDeploymentText $Record.UserSid '^S-1-[0-9]+(?:-[0-9]+)+$' 184)){throw 'User deployment identity requires a literal intended-user SID.'}
    try{$sid=[Security.Principal.SecurityIdentifier]::new($Record.UserSid)}catch{throw 'Invalid deployment user SID.'}
    if($sid.Value -cne $Record.UserSid){throw 'Deployment user SID must use canonical numeric form.'}
  }elseif($null -ne $Record.UserSid){throw 'Machine deployment identity must not carry a user SID.'}
  [pscustomobject][ordered]@{
    SchemaVersion=1;Kind='PackageDeploymentIdentity';DeploymentId=$Record.DeploymentId
    OperationId=$Record.OperationId;PackageId=$Record.PackageId;Variant=$Record.Variant
    LibraryId=$Record.LibraryId;Scope=$Record.Scope;UserSid=$Record.UserSid
    ReadyForMutation=$false
  }
}

function Read-RideDeploymentIdentities {
  param($Records)
  if($null -eq $Records -or $Records -is [string] -or $Records -is [Collections.IDictionary] -or $Records -isnot [Collections.IEnumerable]){throw 'Supply an explicit deployment identity collection.'}
  $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $rows=[Collections.Generic.List[object]]::new()
  foreach($record in $Records){
    if($rows.Count -ge 4096){throw 'Deployment identity collection exceeds 4096 records.'}
    $row=ConvertTo-RideDeploymentIdentity $record
    if(-not $seen.Add($row.DeploymentId)){throw 'Duplicate deployment ID; reconcile the supplied stores explicitly.'}
    $rows.Add($row)
  }
  # Validate the entire collection before exposing any partial result.
  $rows.ToArray()
}

function New-RidePackageDeploymentIdentity {
  <#
  .SYNOPSIS
    Prepare one explicitly named identity from an already resolved package selection.
  .PARAMETER Operation
    Supplied Package metadata with stable Id/PackageId, explicit SelectedVariant,
    effective Scope and optional Library.Id. This function does not resolve defaults.
  .PARAMETER DeploymentId
    New lowercase name, up to 64 characters, beginning with a letter. Not a path.
  .PARAMETER UserSid
    Explicit canonical intended-user SID for User scope; omit for Machine scope.
  .EXAMPLE
    New-RidePackageDeploymentIdentity -Operation $resolvedPackage -DeploymentId sharex-workstation
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 PackageDeploymentIdentity with ReadyForMutation=false.
  .NOTES
    Does not reserve the name or prove installed state, destination ownership,
    coexistence, privileges or current identity. Check collisions in the supplied
    collection separately; actual state-store migration remains unimplemented.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Operation,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DeploymentId,
    [string]$UserSid)
  if($Operation.Kind -cne 'Package' -or $Operation.Variants -or -not $Operation.SelectedVariant){throw 'Supply an explicitly resolved package selection, not a default or unresolved catalog entry.'}
  $library=''
  if($null -ne $Operation.Library){
    if($Operation.Library.Id -isnot [string] -or -not $Operation.Library.Id){throw 'Missing package library identity.'}
    $library=$Operation.Library.Id
  }
  $owner=if($PSBoundParameters.ContainsKey('UserSid')){$UserSid}else{$null}
  ConvertTo-RideDeploymentIdentity ([pscustomobject]@{
    SchemaVersion=1;Kind='PackageDeploymentIdentity';DeploymentId=$DeploymentId
    OperationId=$Operation.Id;PackageId=$Operation.PackageId;Variant=$Operation.SelectedVariant
    LibraryId=$library;Scope=$Operation.Scope;UserSid=$owner;ReadyForMutation=$false
  })
}

function Get-RidePackageDeploymentIdentity {
  <#
  .SYNOPSIS
    Inspect all supplied deployment identities, optionally for one operation.
  .PARAMETER Records
    Explicit collection of schema-1 preparation identities; no implicit state reads.
  .PARAMETER OperationId
    Optional stable catalog operation ID. Completes from the same supplied collection.
  .EXAMPLE
    Get-RidePackageDeploymentIdentity -Records $identities -OperationId package.sharex
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject collection. New objects, with all separate deployments retained.
  .NOTES
    Bounded to 4096 records. Invalid or duplicate identities fail before any result.
    Inspection does not select a preferred deployment or prove installation health.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyCollection()]$Records,
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $prefix=([string]$wordToComplete).Trim("'",'"')
        $ids=@(Get-RidePackageDeploymentIdentity -Records $fakeBoundParameters.Records|ForEach-Object {$_.OperationId}|Sort-Object -Unique)
        foreach($id in $ids){if($id.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($id,$id,'ParameterValue',$id)}}
      }catch{return}
    })][string]$OperationId)
  $rows=@(Read-RideDeploymentIdentities $Records)
  if($PSBoundParameters.ContainsKey('OperationId') -and -not (Test-RideDeploymentText $OperationId '^[a-zA-Z][a-zA-Z0-9.-]+$')){throw 'Invalid operation selector.'}
  foreach($row in $rows){if(-not $OperationId -or $row.OperationId -ieq $OperationId){$row}}
}

function Resolve-RidePackageDeploymentIdentity {
  <#
  .SYNOPSIS
    Select one supplied deployment explicitly, refusing ambiguous product requests.
  .PARAMETER Records
    Explicit collection of schema-1 identities from all relevant stores.
  .PARAMETER DeploymentId
    Optional named deployment; completion reads Records and honors OperationId.
  .PARAMETER OperationId
    Stable operation ID, required when DeploymentId is absent; when both are given
    the selected deployment must belong to that operation. Completion reads Records.
  .EXAMPLE
    Resolve-RidePackageDeploymentIdentity -Records $identities -DeploymentId sharex-portable
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Exactly one copied identity; no default or fallback selection.
  .NOTES
    A product-only request is allowed only for one supplied deployment. Different
    variants, scopes and owners all count toward ambiguity. Catalog defaults and
    preferences do not break ties. Callers must collect complete relevant stores;
    an omitted/inaccessible store cannot be treated as empty by a future writer.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyCollection()]$Records,
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $prefix=([string]$wordToComplete).Trim("'",'"')
        $rows=@(Get-RidePackageDeploymentIdentity -Records $fakeBoundParameters.Records)
        foreach($row in $rows){
          if(( -not $fakeBoundParameters.OperationId -or $row.OperationId -ieq $fakeBoundParameters.OperationId) -and $row.DeploymentId.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){
            [Management.Automation.CompletionResult]::new($row.DeploymentId,$row.DeploymentId,'ParameterValue',($row.OperationId+' / '+$row.Variant+' / '+$row.Scope))
          }
        }
      }catch{return}
    })][string]$DeploymentId,
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $prefix=([string]$wordToComplete).Trim("'",'"')
        $ids=@(Get-RidePackageDeploymentIdentity -Records $fakeBoundParameters.Records|Where-Object {-not $fakeBoundParameters.DeploymentId -or $_.DeploymentId -ieq $fakeBoundParameters.DeploymentId}|ForEach-Object {$_.OperationId}|Sort-Object -Unique)
        foreach($id in $ids){if($id.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($id,$id,'ParameterValue',$id)}}
      }catch{return}
    })][string]$OperationId)
  $rows=@(Read-RideDeploymentIdentities $Records)
  if($PSBoundParameters.ContainsKey('DeploymentId') -and -not (Test-RideDeploymentText $DeploymentId '^[a-zA-Z][a-zA-Z0-9-]*$' 64)){throw 'Invalid deployment selector.'}
  if($PSBoundParameters.ContainsKey('OperationId') -and -not (Test-RideDeploymentText $OperationId '^[a-zA-Z][a-zA-Z0-9.-]+$')){throw 'Invalid operation selector.'}
  if(-not $DeploymentId -and -not $OperationId){throw 'Select a deployment ID or an unambiguous operation ID.'}
  $matches=@($rows|Where-Object {(-not $DeploymentId -or $_.DeploymentId -ieq $DeploymentId) -and (-not $OperationId -or $_.OperationId -ieq $OperationId)})
  if(-not $matches.Count){throw 'No matching deployment identity; no fallback or implicit creation.'}
  if($matches.Count -gt 1){throw 'Multiple deployments match; specify the deployment ID explicitly.'}
  $matches[0]
}

Export-ModuleMember -Function New-RidePackageDeploymentIdentity,Get-RidePackageDeploymentIdentity,Resolve-RidePackageDeploymentIdentity
