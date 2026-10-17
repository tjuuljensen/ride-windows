<#
.SYNOPSIS
  Prepare toolkit file updates while preserving unowned and modified content.
.DESCRIPTION
  Compares supplied prior/desired ownership manifests with a complete supplied
  filesystem observation. Produces explicit stage/remove/keep/conflict decisions
  only. Never reads, copies, replaces or deletes files, nor asks implied approval.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  File/environment inputs: Supplied schema-1 file manifests and filesystem observations.
  Recovery: No mutation. Staging, authenticated ownership, live guards and durable
  commit/interruption recovery remain separate prerequisites for publication.
  Version: 0.1.0.
  Changelog: 0.1.0: Add three-way owned-file comparison with explicit conflicts.
.LINK
  ../docs/migrations/package-deployment-decisions.md
#>
$ErrorActionPreference='Stop'

function ConvertTo-RideToolkitRelativePath {
  param($Value)
  if($Value -isnot [string] -or -not $Value.Length -or $Value.Length -gt 1024 -or $Value -match '[\\:*?"<>|\x00-\x1f]' -or $Value.StartsWith('/') -or $Value.EndsWith('/')){throw 'Toolkit members require bounded relative forward-slash paths.'}
  foreach($part in $Value.Split('/')){
    if(-not $part.Length -or $part -in @('.','..') -or $part.Length -gt 255 -or $part.EndsWith('.') -or $part.EndsWith(' ') -or
        $part -match '^(?i:con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\..*)?$'){throw 'Invalid or reserved toolkit path segment.'}
  }
  $Value
}

function ConvertTo-RideToolkitRoot {
  param($Value)
  if($Value -isnot [string] -or $Value.Length -gt 1024 -or $Value -match '[*?"<>|\x00-\x1f]' -or $Value -match '^\\\\[?.]\\' -or $Value -match '(^|[\\/])\.\.?([\\/]|$)' -or
      $Value -notmatch '^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+[\\/])'){throw 'Toolkit root must be an explicit fully qualified drive or UNC subdirectory.'}
  $root=[IO.Path]::GetFullPath($Value).TrimEnd('\','/')
  if($root -eq [IO.Path]::GetPathRoot($root).TrimEnd('\','/')){throw 'A drive or share root cannot be the toolkit publication root.'}
  $suffix=$root.Substring([IO.Path]::GetPathRoot($root).Length).TrimStart('\','/').Replace('\','/')
  $null=ConvertTo-RideToolkitRelativePath $suffix
  $root
}

function ConvertTo-RideToolkitDigest {
  param($Sha256,$Length)
  if($Sha256 -isnot [string] -or $Sha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
      ($Length -isnot [int] -and $Length -isnot [long] -and $Length -isnot [uint32]) -or $Length -lt 0){throw 'Toolkit file requires a literal SHA-256 and nonnegative byte length.'}
  [pscustomobject]@{Sha256=$Sha256.ToLowerInvariant();Length=[long]$Length}
}

function Read-RideToolkitOwnedFiles {
  param($Manifest,[string]$KitId,[switch]$AllowMissing)
  $files=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
  if($null -eq $Manifest){if($AllowMissing){return ,$files};throw 'Desired toolkit manifest is required.'}
  if(($Manifest.SchemaVersion -isnot [int] -and $Manifest.SchemaVersion -isnot [long]) -or $Manifest.SchemaVersion -ne 1 -or $Manifest.Kind -cne 'ToolkitOwnedFiles' -or
      $Manifest.KitId -cne $KitId -or $null -eq $Manifest.Files -or $Manifest.Files -is [string] -or $Manifest.Files -isnot [Collections.IEnumerable]){throw 'Invalid toolkit owned-files manifest or kit identity.'}
  foreach($file in $Manifest.Files){
    if($files.Count -ge 32768){throw 'Toolkit manifest exceeds 32768 files.'}
    $path=ConvertTo-RideToolkitRelativePath $file.RelativePath
    $digest=ConvertTo-RideToolkitDigest $file.Sha256 $file.Length
    if($files.ContainsKey($path)){throw 'Duplicate toolkit file path, including case variants.'}
    $files.Add($path,[pscustomobject]@{RelativePath=$path;Sha256=$digest.Sha256;Length=$digest.Length})
  }
  foreach($path in $files.Keys){
    $parent=$path
    while($parent.Contains('/')){$parent=$parent.Substring(0,$parent.LastIndexOf('/'));if($files.ContainsKey($parent)){throw 'Toolkit manifest contains a file/descendant path collision.'}}
  }
  ,$files
}

function Read-RideToolkitFilesystemObservation {
  param($Observation,[string]$Root)
  if(($Observation.SchemaVersion -isnot [int] -and $Observation.SchemaVersion -isnot [long]) -or $Observation.SchemaVersion -ne 1 -or $Observation.Kind -cne 'ToolkitFilesystemObservation' -or
      $Observation.Complete -isnot [bool] -or -not $Observation.Complete -or $Observation.CaseSensitive -isnot [bool] -or $Observation.CaseSensitive -or
      $Observation.RootIsReparsePoint -isnot [bool] -or $Observation.RootIsReparsePoint -or (ConvertTo-RideToolkitRoot $Observation.Root) -ine $Root){throw 'Toolkit comparison requires a complete, matching, non-reparse, case-insensitive root observation.'}
  if($null -eq $Observation.Entries -or $Observation.Entries -is [string] -or $Observation.Entries -isnot [Collections.IEnumerable]){throw 'Missing toolkit filesystem entries.'}
  $entries=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($entry in $Observation.Entries){
    if($entries.Count -ge 32768){throw 'Toolkit observation exceeds 32768 entries.'}
    $path=ConvertTo-RideToolkitRelativePath $entry.RelativePath
    if($entry.Kind -cnotin @('File','Directory','ReparsePoint','Unavailable') -or $entries.ContainsKey($path)){throw 'Invalid or duplicate toolkit observation entry.'}
    $digest=if($entry.Kind -ceq 'File'){ConvertTo-RideToolkitDigest $entry.Sha256 $entry.Length}else{[pscustomobject]@{Sha256=$null;Length=$null}}
    if($entry.Kind -cne 'File' -and ($null -ne $entry.Sha256 -or $null -ne $entry.Length)){throw 'Non-file observations must not claim file content.'}
    $entries.Add($path,[pscustomobject]@{RelativePath=$path;Kind=$entry.Kind;Sha256=$digest.Sha256;Length=$digest.Length})
  }
  ,$entries
}

function Test-RideToolkitFileContent {
  param($Actual,$Expected)
  $null -ne $Actual -and $Actual.Kind -ceq 'File' -and $Actual.Sha256 -ceq $Expected.Sha256 -and $Actual.Length -eq $Expected.Length
}

function New-RideToolkitUpdatePreparation {
  <#
  .SYNOPSIS
    Prepare safe owned-file update decisions from supplied manifests and observations.
  .PARAMETER KitId
    Explicit stable lowercase kit name/ID, starting with a letter, at most 64 characters.
  .PARAMETER Root
    Explicit host publication directory below a drive/share root. No USB enrollment.
  .PARAMETER PreviousManifest
    Prior schema-1 ToolkitOwnedFiles ownership record, or explicit null for first publication.
  .PARAMETER DesiredManifest
    Proposed ToolkitOwnedFiles record with exact relative paths, SHA-256 and lengths.
    This file slice is not a complete artifact/license/publication manifest.
  .PARAMETER Observation
    Complete schema-1 ToolkitFilesystemObservation for the same non-reparse root,
    with case-insensitive namespace and explicit file/directory/reparse/unavailable rows.
  .EXAMPLE
    New-RideToolkitUpdatePreparation -KitId field-kit -Root C:\Kits\Field -PreviousManifest $old -DesiredManifest $desired -Observation $observed
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Version-1 ToolkitUpdatePreparation with ordered decisions/conflicts.
  .NOTES
    Staging is required for adds/replacements; no commit is implemented. Modified
    managed replacements/removals, missing managed desired files, unowned collisions
    and unsafe ancestors remain explicit conflicts. Unrelated content is preserved.
    An owned file already matching the desired content is kept without replacing it.
    Complete means supplied coverage, not authenticated live state. This function
    cannot authorize publication, interpret user silence or establish rollback.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$KitId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Root,
    [Parameter(Mandatory)][AllowNull()]$PreviousManifest,
    [Parameter(Mandatory)]$DesiredManifest,[Parameter(Mandatory)]$Observation)
  if($KitId.Length -gt 64 -or $KitId -cnotmatch '^[a-z][a-z0-9-]*$' -or $KitId -match '^(con|prn|aux|nul|com[1-9]|lpt[1-9])$'){throw 'Invalid toolkit ID.'}
  $publicationRoot=ConvertTo-RideToolkitRoot $Root
  $previous=Read-RideToolkitOwnedFiles -Manifest $PreviousManifest -KitId $KitId -AllowMissing
  $desired=Read-RideToolkitOwnedFiles -Manifest $DesiredManifest -KitId $KitId
  $current=Read-RideToolkitFilesystemObservation -Observation $Observation -Root $publicationRoot
  $all=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($dictionary in @($previous,$desired,$current)){foreach($path in $dictionary.Keys){$null=$all.Add($path)}}
  $hasDescendants=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($path in $current.Keys){$parent=$path;while($parent.Contains('/')){$parent=$parent.Substring(0,$parent.LastIndexOf('/'));$null=$hasDescendants.Add($parent)}}
  $decisions=[Collections.Generic.List[object]]::new()
  foreach($path in @($all|Sort-Object)){
    $old=if($previous.ContainsKey($path)){$previous[$path]}else{$null}
    $wanted=if($desired.ContainsKey($path)){$desired[$path]}else{$null}
    $actual=if($current.ContainsKey($path)){$current[$path]}else{$null}
    $action='PreserveUnmanaged';$reason='Unrelated content remains outside ownership.';$blockedAncestor=$null
    $parent=$path
    while($parent.Contains('/')){
      $parent=$parent.Substring(0,$parent.LastIndexOf('/'))
      if($current.ContainsKey($parent) -and $current[$parent].Kind -cne 'Directory'){$blockedAncestor=$parent;break}
    }
    if(($null -ne $wanted -or $null -ne $old) -and $null -ne $blockedAncestor){$action='Conflict';$reason='UnsafeAncestor'}
    elseif(($null -ne $wanted -or $null -ne $old) -and $hasDescendants.Contains($path)){$action='Conflict';$reason='PathHasObservedDescendants'}
    elseif($null -ne $wanted){
      if($null -ne $actual -and $actual.Kind -cne 'File'){$action='Conflict';$reason='NonFileCollision'}
      elseif($null -eq $old){
        if($null -ne $actual){$action='Conflict';$reason='UnownedPath'}else{$action='StageAdd';$reason='New managed file; verify staged content before commit.'}
      }elseif(Test-RideToolkitFileContent $actual $wanted){$action='Keep';$reason='Owned file already matches desired content; no replacement.'}
      elseif($null -eq $actual){$action='Conflict';$reason='MissingManagedFile'}
      elseif(Test-RideToolkitFileContent $actual $old){$action='StageReplace';$reason='Current owned content is unchanged; stage and verify its replacement.'}
      else{$action='Conflict';$reason='ModifiedManagedFile'}
    }elseif($null -ne $old){
      if($null -eq $actual){$action='ForgetAbsent';$reason='Obsolete owned file already absent; no filesystem removal.'}
      elseif(Test-RideToolkitFileContent $actual $old){$action='RemoveOwnedUnchanged';$reason='Obsolete owned file matches its captured digest/length; removal follows verified staging and commit guards.'}
      else{$action='Conflict';$reason='ModifiedOrNonFileObsolete'}
    }
    $decisions.Add([pscustomobject]@{
      RelativePath=if($null -ne $wanted){$wanted.RelativePath}elseif($null -ne $old){$old.RelativePath}else{$actual.RelativePath}
      Action=$action;Reason=$reason;BlockingAncestor=$blockedAncestor
      Previous=$old;Desired=$wanted;Observed=$actual
      RequiresExplicitDecision=($action -ceq 'Conflict')
    })
  }
  $conflicts=@($decisions|Where-Object Action -eq Conflict)
  [pscustomobject]@{
    SchemaVersion=1;Kind='ToolkitUpdatePreparation';KitId=$KitId;Root=$publicationRoot
    Decisions=@($decisions.ToArray());ConflictCount=$conflicts.Count
    StagingRequired=(@($decisions|Where-Object {$_.Action -in @('StageAdd','StageReplace')}).Count -gt 0)
    ReadyForPublication=$false;RecoverySupported=$false
    Limitation='Supplied-data decisions only; requires authenticated ownership/artifact/notices, complete fresh filesystem guards, staging verification and durable commit/recovery'
  }
}

Export-ModuleMember -Function New-RideToolkitUpdatePreparation
