<#
.SYNOPSIS
  Validate data and the exact private Solitaire catalog change for disposable tests.
.DESCRIPTION
  Reads literal catalog/request data only. Permits one SupportedTargets edit for
  app.solitaire; all runtime guards and published source remain unchanged.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add bounded Solitaire-only private fixture data validation.
#>
$ErrorActionPreference='Stop'
function Get-RideSolitaireFixtureCatalog {
  <#
  .SYNOPSIS
    Return one isolated Windows 11 target edit for the reviewed Solitaire identity.
  .PARAMETER Text
    Original literal source catalog text, not a path or executable command.
  .OUTPUTS
    String. Original text with exactly one target-array replacement.
  .NOTES
    Version: 0.1.0. No files or Windows state are changed.
  #>
  param([Parameter(Mandatory)][string]$Text)
  if($Text.Length -gt 2097152){throw 'Fixture catalog exceeds its bound.'}
  $errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$null,[ref]$errors)
  if($errors){throw 'Invalid fixture catalog syntax.'}
  $entries=@($ast.FindAll({param($n)
    if($n -isnot [Management.Automation.Language.HashtableAst]){return $false}
    foreach($pair in $n.KeyValuePairs){
      if($pair.Item1.SafeGetValue() -ceq 'Id' -and $pair.Item2 -is [Management.Automation.Language.PipelineAst] -and $pair.Item2.PipelineElements.Count -eq 1 -and $pair.Item2.PipelineElements[0].Expression.SafeGetValue() -ceq 'app.solitaire'){return $true}
    };$false
  },$true))
  if($entries.Count -ne 1){throw 'Exactly one literal Solitaire entry required.'}
  $entry=$entries[0];$data=$entry.SafeGetValue()
  if($data.Kind -cne 'StoreApp' -or $data.Handler -cne 'StoreApp' -or $data.Scope -cne 'User' -or $data.RequiresAdmin -ne $false -or $data.AppxName -cne 'Microsoft.MicrosoftSolitaireCollection' -or $data.PackageFamilyName -cne 'Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe' -or @($data.SupportedTargets).Count -ne 0 -or $data.PendingAcceptance -ne $true -or 'Windows 11' -notin $data.CandidateTargets -or $data.ProtectionRule -cne 'ReviewedIdentityRemovabilityV1' -or $data.RequireKnownProtectionFlags -ne $true -or $data.ReinstallSource -cne 'RetainedManifestOnly'){throw 'Original Solitaire candidate/protection contract changed.'}
  $target=@($entry.KeyValuePairs|Where-Object {$_.Item1.SafeGetValue() -ceq 'SupportedTargets'})
  if($target.Count -ne 1 -or $target[0].Item2.Extent.Text -cne '@()'){throw 'Original Solitaire target array must be empty.'}
  $extent=$target[0].Item2.Extent
  $Text.Substring(0,$extent.StartOffset)+"@('Windows 11')"+$Text.Substring($extent.EndOffset)
}
function Read-RideSolitaireFixtureRequest {
  <#
  .SYNOPSIS
    Read exact request-bound Solitaire lifecycle metadata without invoking handlers.
  .PARAMETER Path
    Literal bounded JSON fixture path in the staged disposable source.
  .PARAMETER RunId
    Correlated disposable request ID.
  .OUTPUTS
    PSCustomObject. Validated eight-field data.
  .NOTES
    Version: 0.1.0. No alternate app, group, action, package or target selection.
  #>
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$RunId)
  if((Get-Item -LiteralPath $Path).Length -gt 8192){throw 'Oversized Solitaire request.'}
  $r=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
  $keys=@('SchemaVersion','Scenario','RunId','ExpectedUserSid','ExpectedUserName','OperationId','OriginalCatalogSHA256','CandidateCatalogSHA256')
  if(@($r.PSObject.Properties).Count -ne $keys.Count -or @($r.PSObject.Properties.Name|Where-Object {$_ -notin $keys}).Count -or $r.SchemaVersion -ne 1 -or $r.Scenario -cne 'StoreSolitaireLifecycle' -or $r.OperationId -cne 'app.solitaire' -or $r.RunId -cne $RunId -or $RunId -notmatch '^[0-9a-f]{32}$' -or $r.ExpectedUserSid -notmatch '^S-1-5-21-(?:\d+-){3}\d+$' -or $r.ExpectedUserName -notmatch '^[A-Za-z0-9-]{1,15}\\[A-Za-z0-9_-]{1,32}$' -or $r.OriginalCatalogSHA256 -notmatch '^[A-F0-9]{64}$' -or $r.CandidateCatalogSHA256 -notmatch '^[A-F0-9]{64}$'){throw 'Invalid bounded Solitaire-only request.'}
  $r
}
Export-ModuleMember -Function Get-RideSolitaireFixtureCatalog,Read-RideSolitaireFixtureRequest
