<#
.SYNOPSIS
  Compare supplied registrations with catalog distributions for adoption review.
.DESCRIPTION
  Retains all display-name matches and reports per-distribution ambiguity, missing
  sources, target limits and uncovered handlers. No live discovery, file ownership,
  adoption, replacement, installation or uninstallation is performed.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  File/environment inputs: Supplied validated catalog and schema-1 observations.
  Recovery: Read-only preparation; no state store or original installation changes.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded offline registration matching and overlap reporting.
.LINK
  ../docs/application-packages.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.PackageSelection.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.InstalledRegistrationInventory.psm1') -ErrorAction Stop

function Get-RidePackageAdoptionReview {
  <#
  .SYNOPSIS
    Build an offline per-distribution review without selecting or adopting packages.
  .PARAMETER Catalog
    Supplied validated RIDE catalog. Every Package and declared variant is considered.
  .PARAMETER Inventory
    Supplied schema-1 InstalledRegistrationObservation; unavailable/missing views remain explicit.
  .PARAMETER Target
    Explicit catalog target label. Completion reads SupportedTargets in the supplied
    catalog; this label does not authenticate the observation's operating-system target.
  .EXAMPLE
    Get-RidePackageAdoptionReview -Catalog $catalog -Inventory $registrations -Target 'Windows 11'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 PackageAdoptionReview with per-distribution rows/candidates.
  .NOTES
    Only Exe/Msi uninstall-registration name patterns are covered. The regex has a
    50 ms timeout per match and a two-second distribution scan budget; one
    distribution's failure does not block other rows.
    Each single match still requires product/version/architecture/channel/path,
    ownership, current identity and policy validation before adoption. Pending
    targets and portable/service-only distributions are never promoted from a name.
    Shared registrations matching multiple distributions are marked ambiguous.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable]$Catalog,[Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $operations=@($fakeBoundParameters.Catalog.Operations)
        if($operations.Count -gt 4096){return}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $prefix=([string]$wordToComplete).Trim("'",'"')
        foreach($op in $operations){
          $targets=@($op.SupportedTargets)
          if($op.Variants -is [Collections.IDictionary] -and $op.Variants.Count -le 128){foreach($variant in $op.Variants.Values){$targets+=@($variant.SupportedTargets)}}
          foreach($name in $targets){if($name -is [string] -and $name.Length -le 128 -and $name -notmatch '[\x00-\x1f]' -and $name.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($name)){[Management.Automation.CompletionResult]::new(("'"+$name.Replace("'","''")+"'"),$name,'ParameterValue',$name)}}
        }
      }catch{return}
    })][string]$Target)
  if($Catalog.SchemaVersion -ne 1 -or $Target.Length -gt 128 -or $Target -match '[\x00-\x1f]' -or $null -eq $Catalog.Operations -or $Catalog.Operations -isnot [Collections.IEnumerable] -or @($Catalog.Operations).Count -gt 4096){throw 'Expected a bounded validated catalog and explicit target label.'}
  $observed=Get-RideInstalledRegistrationReviewData -Inventory $Inventory
  $views=if($observed.WindowsContext.Is64BitOperatingSystem){@('Registry64','Registry32')}else{@('Registry32')}
  $rows=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($op in $Catalog.Operations){
    if($op.Kind -ne 'Package'){continue}
    if($op -isnot [hashtable] -or $op.Id -isnot [string] -or $op.Id -cnotmatch '^[a-z][a-z0-9.-]+$' -or $op.Id.Length -gt 128 -or -not $seen.Add($op.Id)){throw 'Invalid or duplicate catalog package identity.'}
    if($op.SelectedVariant){throw 'Supply unresolved catalog operations, not saved selections.'}
    $variants=if($op.Variants){@($op.Variants.Keys|Sort-Object)}else{@('installed')}
    if($variants.Count -gt 128 -or $rows.Count+$variants.Count -gt 4096){throw 'Adoption review exceeds bounded distribution count.'}
    foreach($variant in $variants){
      $row=[pscustomobject]@{OperationId=$op.Id;PackageId=$op.PackageId;Variant=$variant;LibraryId=if($op.Library){$op.Library.Id}else{''};Scope=$null;Status='ReviewFailed';Candidates=@();Reasons=@();ObservedTargetVerified=$false;ReadyForAdoption=$false}
      try{
        $selected=Resolve-RidePackageSelection -Operation $op -Variant $variant -MetadataOnly
        $row.Scope=$selected.Scope
        if($selected.Scope -cnotin @('Machine','User')){throw 'Invalid distribution scope.'}
        if($selected.SupportedTargets -notcontains $Target){$row.Status='TargetNotDeclared';$row.Reasons=@('This distribution does not declare the explicitly selected target; no support is inferred.');$rows.Add($row);continue}
        if($selected.InstallerType -notin @('Exe','Msi') -or -not $selected.DisplayNamePattern){$row.Status='NotCovered';$row.Reasons=@('This distribution needs a different identity provider; no uninstall-registry inference.');$rows.Add($row);continue}
        if($selected.DisplayNamePattern -isnot [string] -or $selected.DisplayNamePattern.Length -gt 1024){throw 'Invalid or excessive package display-name pattern.'}
        $regex=[regex]::new($selected.DisplayNamePattern,([Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant),[TimeSpan]::FromMilliseconds(50))
        $incomplete=$false;$matches=[Collections.Generic.List[object]]::new();$timer=[Diagnostics.Stopwatch]::StartNew()
        foreach($view in $views){
          $sources=@($observed.Sources|Where-Object {$_.Scope -ceq $selected.Scope -and $_.RegistryView -ceq $view})
          if($sources.Count -ne 1 -or $sources[0].Status -cne 'Captured'){$incomplete=$true;continue}
          foreach($entry in $sources[0].Entries){
            if($timer.ElapsedMilliseconds -gt 2000){throw 'Distribution registration scan exceeded its time budget.'}
            $display=$entry.Values.DisplayName
            if($display.Exists -and $regex.IsMatch($display.Value)){
              $matches.Add([pscustomobject]@{Scope=$selected.Scope;RegistryView=$view;KeyName=$entry.KeyName;Values=$entry.Values;OverlapsOtherDistributions=$false;IdentityVerified=$false;OwnershipVerified=$false})
            }
          }
        }
        $row.Candidates=@($matches.ToArray())
        $row.Status=if($incomplete){'IncompleteSources'}elseif($matches.Count -gt 1){'Ambiguous'}elseif($matches.Count -eq 1){'SingleCandidate'}else{'NoMatch'}
        $row.Reasons=@('Display-name matching is provisional; product, version, architecture/channel, location and ownership still need verification.')
        if($incomplete){$row.Reasons+=@('One or more required scope/views is missing or unavailable; no absence or unique-match conclusion.')}
      }catch{$row.Status='ReviewFailed';$row.Candidates=@();$row.Reasons=@('Distribution review failed: '+$_.Exception.GetType().FullName)}
      $rows.Add($row)
    }
  }
  $owners=[Collections.Generic.Dictionary[string,Collections.Generic.HashSet[string]]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($row in $rows){foreach($candidate in $row.Candidates){
    # Length-prefix the opaque registry key; IDs are not filesystem paths.
    $key=$candidate.Scope+'/'+$candidate.RegistryView+'/'+$candidate.KeyName.Length+':'+$candidate.KeyName
    if(-not $owners.ContainsKey($key)){$owners[$key]=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)}
    $null=$owners[$key].Add($row.OperationId+'/'+$row.Variant)
  }}
  foreach($row in $rows){foreach($candidate in $row.Candidates){
    $key=$candidate.Scope+'/'+$candidate.RegistryView+'/'+$candidate.KeyName.Length+':'+$candidate.KeyName
    if($owners[$key].Count -gt 1){$candidate.OverlapsOtherDistributions=$true;if($row.Status -ceq 'SingleCandidate'){$row.Status='Ambiguous'};$row.Reasons+=@('A matching registration also matches another catalog distribution; resolve it individually.')}
  }}
  [pscustomobject]@{SchemaVersion=1;Kind='PackageAdoptionReview';Target=$Target;WindowsContext=$observed.WindowsContext;Rows=@($rows.ToArray());ReadyForMutation=$false;RecoverySupported=$false;Limitation='Supplied-data review only; no live validation, ownership, adoption, upgrade, replacement or removal authorization'}
}

Export-ModuleMember -Function Get-RidePackageAdoptionReview
