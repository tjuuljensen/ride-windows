<#
.SYNOPSIS
  Check offline bundle content and assemble explicit local sources into new folders.
.DESCRIPTION
  Validates a schema-1 manifest and verifies the engine, selected profile and its
  declared dependency closure against local files. Unrelated omissions do not
  block selected content. Hashes are integrity checks, not publisher authentication
  or proof that dependency declarations and offline installer behavior are complete.
  Assembly writes a new local staging/final folder only; it retains failed staging
  and prior versions. Preflight functions are read-only.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: 0.7.0.
  Changelog: 0.7.0: Optionally gate assembly on byte-bound selected-profile coverage.
    0.6.0: Compare explicit catalog download sources during package coverage.
    0.5.0: Reverify all staged files after copying and before commit metadata.
    0.4.0: Assemble explicit local sources into a new verified bundle folder.
    0.3.0: Bind optional profile coverage to locally captured file bytes.
    0.2.0: Compare pinned profile/catalog package requirements with manifests.
    0.1.0: Add bounded local integrity/dependency preflight for one profile.
  No installer, provider, source acquisition, external publication, prune or target change.
.LINK
  ../docs/offline-bundles.md
#>
$ErrorActionPreference='Stop'

function Assert-RideBundleFields {
  param($Object,[string[]]$Required,[string[]]$Optional=@())
  if($null -eq $Object -or ($Object -isnot [Collections.IDictionary] -and $Object -isnot [pscustomobject])){throw 'Bundle object is missing or malformed.'}
  $names=if($Object -is [Collections.IDictionary]){@($Object.Keys)}else{@($Object.PSObject.Properties.Name)}
  foreach($name in $Required){if($name -cnotin $names){throw 'Bundle object is missing a required field.'}}
  foreach($name in $names){if($name -cnotin $Required -and $name -cnotin $Optional){throw 'Bundle object contains an unknown field.'}}
}
function Assert-RideBundleToken {
  param($Value)
  if($Value -isnot [string] -or $Value -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,159}$'){throw 'Bundle identity/version must be a bounded literal token.'}
}
function Assert-RideBundleList {
  param($Value,[int]$Maximum=4096)
  if($null -eq $Value -or $Value -is [string] -or $Value -isnot [Collections.IEnumerable] -or @($Value).Count -gt $Maximum){throw 'Bundle list is missing or excessive.'}
}
function Get-RideBundleIds {
  param($Value)
  Assert-RideBundleList $Value
  $seen=@{};$result=@(foreach($id in $Value){Assert-RideBundleToken $id;if($seen.ContainsKey($id)){throw 'Duplicate bundle reference.'};$seen[$id]=$true;[string]$id})
  return ,$result
}
function Assert-RideBundleRelativePath {
  param($Path)
  if($Path -isnot [string] -or -not $Path -or $Path.Length -gt 1024 -or $Path -match '[\\:*?"<>|\x00-\x1f]' -or $Path.StartsWith('/') -or $Path.EndsWith('/')){throw 'Bundle file requires a bounded relative forward-slash path.'}
  foreach($part in $Path.Split('/')){
    if(-not $part -or $part -in @('.','..') -or $part.Length -gt 255 -or $part.EndsWith('.') -or $part.EndsWith(' ') -or
        $part -match '^(?i:con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\..*)?$'){throw 'Invalid or reserved bundle path segment.'}
  }
}
function Assert-RideBundleHttps {
  param($Value,[switch]$AllowFragment)
  if($Value -isnot [string] -or $Value.Length -gt 2048){throw 'Invalid bundle publisher reference.'}
  $uri=$null
  if(-not [uri]::TryCreate($Value,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or -not $uri.IsDefaultPort -or $uri.UserInfo -or ($uri.Fragment -and -not $AllowFragment)){throw 'Bundle publisher reference requires HTTPS without credentials; artifact URLs cannot contain fragments.'}
}
function Read-RideBundleIndex {
  param($Manifest)
  Assert-RideBundleFields $Manifest @('SchemaVersion','Kind','BundleId','BundleVersion','Engine','Files','Artifacts','ServicingSources','Profiles')
  if(($Manifest.SchemaVersion -isnot [int] -and $Manifest.SchemaVersion -isnot [long]) -or $Manifest.SchemaVersion -ne 1 -or $Manifest.Kind -cne 'RideOfflineBundle'){throw 'Unsupported offline bundle schema/kind.'}
  Assert-RideBundleToken $Manifest.BundleId;Assert-RideBundleToken $Manifest.BundleVersion
  Assert-RideBundleFields $Manifest.Engine @('Version','SourceCommit','FileIds')
  Assert-RideBundleToken $Manifest.Engine.Version
  if($Manifest.Engine.SourceCommit -isnot [string] -or $Manifest.Engine.SourceCommit -cnotmatch '^[a-fA-F0-9]{40}$'){throw 'Engine source requires a pinned full Git commit identity.'}
  $engineFiles=Get-RideBundleIds $Manifest.Engine.FileIds
  if(-not $engineFiles.Count){throw 'Bundle requires explicit engine files.'}
  Assert-RideBundleList $Manifest.Files 32768
  $files=@{};$paths=@{}
  foreach($file in $Manifest.Files){
    Assert-RideBundleFields $file @('Id','RelativePath','Role','Sha256','Length')
    Assert-RideBundleToken $file.Id;Assert-RideBundleRelativePath $file.RelativePath
    if($file.Role -cnotin @('Engine','Profile','Payload','Notice','ServicingSource') -or
        $file.Sha256 -isnot [string] -or $file.Sha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
        ($file.Length -isnot [int] -and $file.Length -isnot [long] -and $file.Length -isnot [uint32]) -or $file.Length -lt 0 -or
        $files.ContainsKey($file.Id) -or $paths.ContainsKey($file.RelativePath)){throw 'Invalid or duplicate bundle file identity/digest/length.'}
    $files[$file.Id]=$file;$paths[$file.RelativePath]=$true
  }
  foreach($path in $paths.get_Keys()){$parent=$path;while($parent.Contains('/')){$parent=$parent.Substring(0,$parent.LastIndexOf('/'));if($paths.ContainsKey($parent)){throw 'Bundle file/descendant collision.'}}}
  foreach($id in $engineFiles){if(-not $files.ContainsKey($id) -or $files[$id].Role -cne 'Engine'){throw 'Engine references an unknown or non-engine file.'}}
  $artifacts=@{};Assert-RideBundleList $Manifest.Artifacts
  foreach($artifact in $Manifest.Artifacts){
    Assert-RideBundleFields $artifact @('Id','PackageId','Variant','Version','Architecture','Targets','Status','OmissionCode','FileIds','DependencyIds','OfflineCapability','ProductUri','DownloadUri','License','LicenseUri') @('TermsUri')
    foreach($name in @('Id','PackageId','Variant','Version','Architecture')){Assert-RideBundleToken $artifact.$name}
    Assert-RideBundleHttps $artifact.DownloadUri
    foreach($name in @('ProductUri','LicenseUri')){Assert-RideBundleHttps $artifact.$name -AllowFragment}
    if($artifact.TermsUri){Assert-RideBundleHttps $artifact.TermsUri -AllowFragment}
    if($artifact.License -isnot [string] -or -not $artifact.License -or $artifact.License.Length -gt 1024){throw 'Missing descriptive artifact licence metadata.'}
    Assert-RideBundleList $artifact.Targets 32
    if(-not @($artifact.Targets).Count -or @($artifact.Targets|Where-Object {$_ -isnot [string] -or -not $_ -or $_.Length -gt 128}).Count){throw 'Artifact requires explicit bounded target names.'}
    $fileIds=Get-RideBundleIds $artifact.FileIds;$null=Get-RideBundleIds $artifact.DependencyIds
    if($artifact.Status -cnotin @('Included','Omitted') -or $artifact.OfflineCapability -cnotin @('Unverified','DeclaredNoNetwork','NetworkRequired') -or $artifacts.ContainsKey($artifact.Id)){throw 'Invalid artifact status/capability or duplicate identity.'}
    if($artifact.Status -ceq 'Included'){
      if($artifact.OmissionCode -or -not $fileIds.Count){throw 'Included artifact requires files and no omission code.'}
      $payloadCount=0
      foreach($id in $fileIds){if(-not $files.ContainsKey($id) -or $files[$id].Role -cnotin @('Payload','Notice')){throw 'Artifact references an invalid payload/notice file.'};if($files[$id].Role -ceq 'Payload'){$payloadCount++}}
      if(-not $payloadCount){throw 'Included artifact has no payload.'}
    }elseif($fileIds.Count -or $artifact.OmissionCode -cnotin @('Missing','Restricted','TechnicalPending')){throw 'Omitted artifact requires a reason and no included file claims.'}
    $artifacts[$artifact.Id]=$artifact
  }
  foreach($artifact in $artifacts.get_Values()){foreach($id in $artifact.DependencyIds){if(-not $artifacts.ContainsKey($id)){throw 'Artifact dependency must have an included or omitted manifest record.'}}}
  $servicing=@{};Assert-RideBundleList $Manifest.ServicingSources 256
  foreach($source in $Manifest.ServicingSources){
    Assert-RideBundleFields $source @('Id','Status','OmissionCode','FileIds','Target','Build','EditionId','Architecture','Compatibility')
    Assert-RideBundleToken $source.Id;Assert-RideBundleToken $source.Architecture
    if($servicing.ContainsKey($source.Id) -or $artifacts.ContainsKey($source.Id) -or $source.Status -cnotin @('Included','Omitted') -or $source.Compatibility -cne 'Unverified' -or
        $source.Target -isnot [string] -or -not $source.Target -or $source.Target.Length -gt 128 -or
        ($source.Build -isnot [int] -and $source.Build -isnot [long]) -or $source.Build -lt 1000 -or $source.Build -gt 99999999 -or
        $source.EditionId -isnot [string] -or -not $source.EditionId -or $source.EditionId.Length -gt 128){throw 'Invalid servicing metadata; native compatibility remains Unverified.'}
    $sourceFiles=Get-RideBundleIds $source.FileIds
    if($source.Status -ceq 'Included'){
      if($source.OmissionCode -or -not $sourceFiles.Count){throw 'Included servicing source requires files.'}
      foreach($id in $sourceFiles){if(-not $files.ContainsKey($id) -or $files[$id].Role -cne 'ServicingSource'){throw 'Unknown servicing file.'}}
    }elseif($sourceFiles.Count -or $source.OmissionCode -cnotin @('Missing','Restricted','TechnicalPending')){throw 'Omitted servicing source requires a reason.'}
    $servicing[$source.Id]=$source
  }
  $profiles=@{};Assert-RideBundleList $Manifest.Profiles 256
  foreach($profile in $Manifest.Profiles){
    Assert-RideBundleFields $profile @('Id','FileId','Target','Build','EditionId','Architecture','ArtifactIds','ServicingSourceIds')
    Assert-RideBundleToken $profile.Id;Assert-RideBundleToken $profile.Architecture
    if($profiles.ContainsKey($profile.Id) -or -not $files.ContainsKey($profile.FileId) -or $files[$profile.FileId].Role -cne 'Profile' -or
        $profile.Target -isnot [string] -or -not $profile.Target -or $profile.Target.Length -gt 128 -or
        ($profile.Build -isnot [int] -and $profile.Build -isnot [long]) -or $profile.Build -lt 1000 -or $profile.Build -gt 99999999 -or
        $profile.EditionId -isnot [string] -or -not $profile.EditionId -or $profile.EditionId.Length -gt 128){throw 'Invalid or duplicate bundle profile.'}
    foreach($id in (Get-RideBundleIds $profile.ArtifactIds)){if(-not $artifacts.ContainsKey($id)){throw 'Unknown profile artifact requirement.'}}
    foreach($id in (Get-RideBundleIds $profile.ServicingSourceIds)){if(-not $servicing.ContainsKey($id)){throw 'Unknown profile servicing requirement.'}}
    $profiles[$profile.Id]=$profile
  }
  if(-not $profiles.get_Count()){throw 'Bundle has no selected-profile definition.'}
  [pscustomobject]@{Files=$files;Artifacts=$artifacts;Servicing=$servicing;Profiles=$profiles;EngineFileIds=$engineFiles}
}

function Get-RideBundlePathAttributes {
  param([string]$Path)
  [IO.File]::GetAttributes($Path)
}
function Open-RideBundleReadStream {
  param([string]$Path)
  [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
}
function Get-RideBundleFileObservation {
  param([string]$Root,$File)
  $stream=$null;$algorithm=$null
  $result=[pscustomobject]@{Id=$File.Id;RelativePath=$File.RelativePath;Status='Unavailable';Length=$null;Sha256=$null;ErrorId=$null}
  try{
    $path=$Root
    foreach($part in $File.RelativePath.Split('/')){
      $path=Join-Path $path $part
      if(-not (Test-Path -LiteralPath $path)){$result.Status='Missing';return $result}
      $attributes=Get-RideBundlePathAttributes $path
      if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$result.Status='ReparsePoint';return $result}
    }
    if(($attributes -band [IO.FileAttributes]::Directory) -ne 0){$result.Status='NotAFile';return $result}
    $stream=Open-RideBundleReadStream $path
    $result.Length=$stream.Length
    if($stream.Length -ne $File.Length){$result.Status='LengthMismatch';return $result}
    $algorithm=[Security.Cryptography.SHA256]::Create()
    $result.Sha256=([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','').ToLowerInvariant()
    $result.Status=if($result.Sha256 -ieq $File.Sha256){'Verified'}else{'HashMismatch'}
  }catch{$result.Status='Unavailable';$result.ErrorId=$_.Exception.GetType().FullName}
  finally{if($algorithm){$algorithm.Dispose()};if($stream){$stream.Dispose()}}
  $result
}

function Read-RideBundleBoundText {
  param([string]$Root,$File,[int]$MaximumBytes)
  if($File.Length -gt $MaximumBytes){throw 'Bundle source exceeds its bounded parser size.'}
  $path=$Root;$ancestor=$Root
  while($ancestor){if(((Get-RideBundlePathAttributes $ancestor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Bundle source ancestry contains a reparse point.'};$ancestor=[IO.Path]::GetDirectoryName($ancestor)}
  foreach($part in $File.RelativePath.Split('/')){
    $path=Join-Path $path $part
    if(((Get-RideBundlePathAttributes $path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Bundle source path contains a reparse point.'}
  }
  $stream=Open-RideBundleReadStream $path
  try{
    if($stream.Length -ne $File.Length -or $stream.Length -gt $MaximumBytes){throw 'Bundle source length changed or exceeds its parser bound.'}
    $bytes=[byte[]]::new([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$read=$stream.Read($bytes,$offset,$bytes.Length-$offset);if(-not $read){throw 'Incomplete bundle source read.'};$offset+=$read}
  }finally{$stream.Dispose()}
  $algorithm=[Security.Cryptography.SHA256]::Create()
  try{$sha256=([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
  if($sha256 -ine $File.Sha256){throw 'Bundle source changed before parsing; digest mismatch.'}
  $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)
  [pscustomobject]@{Text=$text;Sha256=$sha256}
}

function ConvertFrom-RideBundleProfileText {
  param([string]$Text)
  $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
  if($errors.Count -or $ast.BeginBlock -or $ast.ProcessBlock -or $ast.ParamBlock -or $ast.EndBlock.Statements.Count -ne 1){throw 'Invalid declarative bundle profile syntax.'}
  $statement=$ast.EndBlock.Statements[0]
  if($statement -isnot [Management.Automation.Language.PipelineAst] -or $statement.PipelineElements.Count -ne 1){throw 'Bundle profile requires a single declarative hashtable.'}
  $root=$statement.PipelineElements[0].Expression
  if($root -isnot [Management.Automation.Language.HashtableAst]){throw 'Bundle profile requires a declarative hashtable.'}
  $profile=$root.SafeGetValue()
  Assert-RideBundleFields $profile @('SchemaVersion','Name','Operations') @('Description')
  $profile
}

function Test-RideOfflineBundle {
  <#
  .SYNOPSIS
    Verify local files for one manifest-declared profile and dependency closure.
  .PARAMETER Manifest
    Parsed schema-1 RideOfflineBundle metadata; validation precedes all file reads.
  .PARAMETER Root
    Existing explicit local drive subdirectory holding the transferred bundle.
  .PARAMETER ProfileId
    Exact manifest profile ID; completion is read-only against supplied metadata.
  .PARAMETER MaximumBytes
    Upper bound for total declared selected file bytes; default 128 GiB.
  .EXAMPLE
    Test-RideOfflineBundle -Manifest $manifest -Root C:\Offline\bundle-v1 -ProfileId workstation
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Selected declared content integrity and unresolved offline gates.
  .NOTES
    Never falls back to network, executes bundled code or changes target state.
    Declared content completeness is not dependency discovery or native eligibility.
    The main install/apply commands do not yet consume this preflight.
  .PARAMETER CatalogFileId
    Optional Engine file ID containing the pinned catalog. Enables byte-bound
    comparison against the selected bundled profile using trusted local parsers.
    Catalog and profile limits are 2 MiB and 64 KiB. No bundled code is imported.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Manifest,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Root,
    [Parameter(Mandatory)]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $rows=@($fakeBoundParameters['Manifest'].Profiles)
        if($rows.Count -gt 256){return}
        $rows|Where-Object {$_.Id -is [string] -and $_.Id.StartsWith($wordToComplete.Trim("'",'"'),[StringComparison]::OrdinalIgnoreCase)}|Sort-Object Id -Unique|ForEach-Object {
          [Management.Automation.CompletionResult]::new(("'"+$_.Id.Replace("'","''")+"'"),$_.Id,'ParameterValue',$_.Id)
        }
      }catch{}
    })]
    [ValidateNotNullOrEmpty()][string]$ProfileId,
    [ValidateRange(1,1099511627776)][long]$MaximumBytes=137438953472,
    [ArgumentCompleter({param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $attribute=(Get-Command Test-RideOfflineProfileCoverage).Parameters['CatalogFileId'].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
        & $attribute.ScriptBlock $commandName $parameterName $wordToComplete $commandAst $fakeBoundParameters
      }catch{}
    })][string]$CatalogFileId
  )
  $index=Read-RideBundleIndex $Manifest
  if(-not $index.Profiles.ContainsKey($ProfileId)){throw 'Selected profile is absent from this bundle.'}
  if($CatalogFileId -and ($CatalogFileId -notin $index.EngineFileIds -or $index.Files[$CatalogFileId].Length -gt 2MB -or $index.Files[$index.Profiles[$ProfileId].FileId].Length -gt 64KB)){throw 'Coverage requires a catalog Engine file no larger than 2 MiB and a profile no larger than 64 KiB.'}
  if($Root -notmatch '^[A-Za-z]:[\\/]' -or $Root -match '[*?"<>|\x00-\x1f]' -or $Root -match '(^|[\\/])\.\.?([\\/]|$)'){throw 'Bundle root must be an explicit local drive subdirectory without traversal.'}
  $rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\','/')
  if($rootPath -eq [IO.Path]::GetPathRoot($rootPath).TrimEnd('\','/') -or -not [IO.Directory]::Exists($rootPath)){throw 'Bundle root must be an existing subdirectory.'}
  $ancestor=$rootPath
  while($ancestor){if(((Get-RideBundlePathAttributes $ancestor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Bundle root ancestry contains a reparse point.'};$ancestor=[IO.Path]::GetDirectoryName($ancestor)}
  $profile=$index.Profiles[$ProfileId];$visited=@{};$active=@{};$ordered=[Collections.Generic.List[string]]::new()
  function Visit-BundleArtifact([string]$Id,[int]$Depth){
    if($Depth -gt 128 -or $active.ContainsKey($Id)){throw 'Offline dependency graph is cyclic or exceeds depth 128.'}
    if($visited.ContainsKey($Id)){return};$active[$Id]=$true
    foreach($dependency in $index.Artifacts[$Id].DependencyIds){Visit-BundleArtifact $dependency ($Depth+1)}
    $active.Remove($Id);$visited[$Id]=$true;$ordered.Add($Id)
  }
  foreach($id in $profile.ArtifactIds){Visit-BundleArtifact $id 0}
  $required=@{};foreach($id in $index.EngineFileIds){$required[$id]=$true};$required[$profile.FileId]=$true
  $issues=[Collections.Generic.List[object]]::new();$gates=[Collections.Generic.List[object]]::new()
  foreach($id in $ordered){
    $artifact=$index.Artifacts[$id]
    if($artifact.Status -ceq 'Omitted'){$issues.Add([pscustomobject]@{Id=$id;Reason=$artifact.OmissionCode});continue}
    foreach($fileId in $artifact.FileIds){$required[$fileId]=$true}
    if($profile.Target -notin $artifact.Targets -or ($artifact.Architecture -ine 'any' -and $artifact.Architecture -ine $profile.Architecture)){$issues.Add([pscustomobject]@{Id=$id;Reason='DeclaredTargetOrArchitectureMismatch'})}
    if($artifact.OfflineCapability -cne 'DeclaredNoNetwork'){$gates.Add([pscustomobject]@{Id=$id;Reason=$artifact.OfflineCapability})}
  }
  foreach($id in $profile.ServicingSourceIds){
    $source=$index.Servicing[$id]
    if($source.Status -ceq 'Omitted'){$issues.Add([pscustomobject]@{Id=$id;Reason=$source.OmissionCode});continue}
    foreach($fileId in $source.FileIds){$required[$fileId]=$true}
    if($source.Target -ine $profile.Target -or $source.Build -ne $profile.Build -or $source.EditionId -ine $profile.EditionId -or $source.Architecture -ine $profile.Architecture){$issues.Add([pscustomobject]@{Id=$id;Reason='DeclaredServicingMetadataMismatch'})}
    $gates.Add([pscustomobject]@{Id=$id;Reason='NativeServicingCompatibilityUnverified'})
  }
  [long]$total=0
  foreach($id in $required.get_Keys()){$length=[long]$index.Files[$id].Length;if($length -gt $MaximumBytes-$total){throw 'Selected bundle content exceeds the explicit byte bound.'};$total+=$length}
  $started=[DateTime]::UtcNow.ToString('o')
  $observations=@(foreach($id in @($required.get_Keys()|Sort-Object)){Get-RideBundleFileObservation -Root $rootPath -File $index.Files[$id]})
  $fileIssues=@($observations|Where-Object Status -cne 'Verified')
  $omissions=@(@($index.Artifacts.get_Values())+@($index.Servicing.get_Values())|Where-Object Status -ceq 'Omitted'|Sort-Object Id|ForEach-Object {[pscustomobject]@{Id=$_.Id;Reason=$_.OmissionCode}})
  $result=[pscustomobject]@{
    SchemaVersion=1;Kind='RideOfflineBundlePreflight';BundleId=$Manifest.BundleId;BundleVersion=$Manifest.BundleVersion
    ProfileId=$profile.Id;EngineVersion=$Manifest.Engine.Version;EngineSourceCommit=$Manifest.Engine.SourceCommit
    DeclaredTarget=[pscustomobject]@{Name=$profile.Target;Build=$profile.Build;EditionId=$profile.EditionId;Architecture=$profile.Architecture;Observed=$false}
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o');DeclaredSelectedBytes=$total
    RequiredArtifactIds=$ordered.ToArray();Files=$observations;RequirementIssues=$issues.ToArray();OfflineGates=$gates.ToArray();BundleOmissions=$omissions
    BundleDeclaredStatus=$(if($omissions.Count){'Incomplete'}else{'NoDeclaredOmissions'});IntegrityCoverage='SelectedProfileAndDeclaredDependencies'
    SelectedDeclaredContentComplete=($issues.Count -eq 0 -and $fileIssues.Count -eq 0)
    ManifestCoverageVerified=$false;EngineSourceCommitVerified=$false;ProfileDependencyClosureVerified=$false;ActualTargetVerified=$false
    NetworkFallbackAllowed=$false;ReadyForMutation=$false;RecoverySupported=$false
    ProfileCoverageStatus='NotRequested';ProfileCoverage=$null;SelectedPackageContentComplete=$null
  }
  if($CatalogFileId){
    $result.SelectedPackageContentComplete=$false
    $sourceIssues=@($observations|Where-Object {$_.Id -in @($CatalogFileId,$profile.FileId) -and $_.Status -cne 'Verified'})
    if($sourceIssues.Count){$result.ProfileCoverageStatus='SourceUnavailable'}
    else{
      $catalogText=Read-RideBundleBoundText -Root $rootPath -File $index.Files[$CatalogFileId] -MaximumBytes 2MB
      $profileText=Read-RideBundleBoundText -Root $rootPath -File $index.Files[$profile.FileId] -MaximumBytes 64KB
      Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1') -ErrorAction Stop
      $catalogData=Import-RideCatalogData -Content $catalogText.Text
      $profileData=ConvertFrom-RideBundleProfileText $profileText.Text
      $coverage=Test-RideOfflineProfileCoverage -Manifest $Manifest -ProfileId $ProfileId -CatalogFileId $CatalogFileId -Catalog $catalogData -Profile $profileData -CatalogSha256 $catalogText.Sha256 -ProfileSha256 $profileText.Sha256
      $coverage.ParsedBytesBindingVerified=$true
      $result.ProfileCoverage=$coverage;$result.ProfileCoverageStatus='Compared'
      $result.SelectedPackageContentComplete=($result.SelectedDeclaredContentComplete -and $coverage.SelectedPackageDeclarationsComplete)
    }
  }
  $result
}
function Test-RideOfflineProfileCoverage {
  <#
  .SYNOPSIS
    Find missing package declarations using supplied pinned catalog/profile data.
  .DESCRIPTION
    Expands ordinary package groups and declared PrerequisitePackageId links.
    Requires explicit variants where catalog variants exist; no host preferences
    or existing installation are queried. Compares manifest-selected artifacts,
    source hashes, product/licence metadata and declared version/digest pins.
    This data-only comparison complements, but does not run, file integrity checks.
  .PARAMETER Manifest
    Schema-1 RideOfflineBundle manifest. PackageId means the stable catalog ID.
  .PARAMETER ProfileId
    Manifest profile whose selected artifact closure is compared.
  .PARAMETER CatalogFileId
    Manifest Engine file record for the exact supplied catalog bytes.
  .PARAMETER Catalog
    Validated schema-1 declarative catalog. No bundled module is imported.
  .PARAMETER Profile
    Effective schema-1 profile with explicit desired states and package variants.
    Flatten a group containing variant choices into individual package selections.
  .PARAMETER CatalogSha256
    SHA-256 of the exact bytes parsed as Catalog, calculated by the caller.
  .PARAMETER ProfileSha256
    SHA-256 of the exact bytes parsed as Profile, calculated by the caller.
  .EXAMPLE
    Test-RideOfflineProfileCoverage -Manifest $manifest -ProfileId workstation -CatalogFileId catalog -Catalog $catalog -Profile $profile -CatalogSha256 $catalogHash -ProfileSha256 $profileHash
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 coverage report; never an installation authorization.
  .NOTES
    Caller-supplied hashes are assertions unless bound to the parsed bytes by a
    trusted reader. No actual files, host hardware, preferences, publisher source,
    installer dependencies, licensing assessment or native behavior is verified.
    Unsupported/conditional selection fields are refused rather than ignored.
    Removed packages require separate recovery/uninstaller source evaluation.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Manifest,
    [Parameter(Mandatory)]
    [ArgumentCompleter({param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{if(@($fakeBoundParameters.Manifest.Profiles).Count -gt 256){return};foreach($p in @($fakeBoundParameters.Manifest.Profiles|Sort-Object Id -Unique)){
        if($p.Id -is [string] -and $p.Id -match '^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,159}$' -and $p.Id.StartsWith($wordToComplete.Trim("'",'"'),[StringComparison]::OrdinalIgnoreCase)){
          [Management.Automation.CompletionResult]::new(("'"+$p.Id+"'"),$p.Id,'ParameterValue',$p.Id)
        }
      }}catch{}
    })][string]$ProfileId,
    [Parameter(Mandatory)]
    [ArgumentCompleter({param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{if(@($fakeBoundParameters.Manifest.Files).Count -gt 32768 -or @($fakeBoundParameters.Manifest.Engine.FileIds).Count -gt 4096){return};foreach($f in @($fakeBoundParameters.Manifest.Files|Where-Object {$_.Role -ceq 'Engine' -and $_.Id -in $fakeBoundParameters.Manifest.Engine.FileIds}|Sort-Object Id -Unique)){
        if($f.Id -is [string] -and $f.Id -match '^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,159}$' -and $f.Id.StartsWith($wordToComplete.Trim("'",'"'),[StringComparison]::OrdinalIgnoreCase)){
          [Management.Automation.CompletionResult]::new(("'"+$f.Id+"'"),$f.Id,'ParameterValue',$f.RelativePath)
        }
      }}catch{}
    })][string]$CatalogFileId,
    [Parameter(Mandatory)][hashtable]$Catalog,
    [Parameter(Mandatory)][hashtable]$Profile,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$CatalogSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ProfileSha256
  )
  $index=Read-RideBundleIndex $Manifest
  if(-not $index.Profiles.ContainsKey($ProfileId)){throw 'Unknown bundle profile.'}
  $selected=$index.Profiles[$ProfileId]
  if($CatalogFileId -notin $index.EngineFileIds -or $index.Files[$CatalogFileId].Sha256 -ine $CatalogSha256 -or
      $index.Files[$selected.FileId].Sha256 -ine $ProfileSha256){throw 'Catalog/profile source hashes do not match pinned manifest file records.'}
  if($Catalog.SchemaVersion -ne 1 -or $Profile.SchemaVersion -ne 1 -or
      $Profile.Name -isnot [string] -or -not $Profile.Name -or $Profile.Name.Length -gt 255){throw 'Invalid catalog/profile source schema.'}
  Assert-RideBundleList $Catalog.Operations 2000;Assert-RideBundleList $Catalog.Groups 2000
  Assert-RideBundleList $Profile.Operations 2000
  if(-not @($Profile.Operations).Count -or @($Catalog.Operations).Count+@($Catalog.Groups).Count -gt 2000){throw 'Empty or excessive profile/catalog.'}
  $ops=@{};$groups=@{}
  foreach($op in $Catalog.Operations){
    if($op -isnot [hashtable]){throw 'Catalog operation must be declarative data.'};Assert-RideBundleToken $op.Id
    if($ops.ContainsKey($op.Id)){throw 'Duplicate catalog operation.'};$ops[$op.Id]=$op
  }
  foreach($group in $Catalog.Groups){
    if($group -isnot [hashtable]){throw 'Catalog group must be declarative data.'};Assert-RideBundleToken $group.Id
    if($ops.ContainsKey($group.Id) -or $groups.ContainsKey($group.Id)){throw 'Duplicate catalog identity.'};$groups[$group.Id]=$group
  }
  Import-Module (Join-Path $PSScriptRoot 'RIDE.PackageSelection.psm1') -ErrorAction Stop
  $issues=[Collections.Generic.List[object]]::new();$requirements=[Collections.Generic.List[object]]::new()
  $other=[Collections.Generic.List[object]]::new();$seen=@{};$explicit=@{};$expanded=[Collections.Generic.List[object]]::new()
  foreach($selection in $Profile.Operations){
    if($selection -isnot [hashtable]){throw 'Invalid effective profile selection.'}
    Assert-RideBundleFields $selection @('Id','State') @('Variant')
    Assert-RideBundleToken $selection.Id;Assert-RideBundleToken $selection.State
    if($explicit.ContainsKey($selection.Id)){throw 'Duplicate/conflicting profile selection.'};$explicit[$selection.Id]=$true
    if($groups.ContainsKey($selection.Id)){
      $group=$groups[$selection.Id]
      if($group.Workflow -or $selection.ContainsKey('Variant') -or $selection.State -notin @('Present','Absent')){throw 'Unsupported workflow/group selection; use a reviewed effective package profile.'}
      $members=Get-RideBundleIds $group.Members
      if(-not $members.Count){throw 'Empty group.'}
      if($selection.State -eq 'Absent'){[array]::Reverse($members)}
      foreach($id in $members){
        if(-not $ops.ContainsKey($id) -or $ops[$id].Kind -ne 'Package'){throw 'Offline group coverage requires direct package members.'}
        $expanded.Add(@{Id=$id;State=$selection.State;Origin=$group.Id})
      }
    }elseif($ops.ContainsKey($selection.Id)){$item=$selection.Clone();$item.Origin=$selection.Id;$expanded.Add($item)}
    else{throw 'Unknown profile identity.'}
  }
  foreach($selection in $expanded){
    if($seen.ContainsKey($selection.Id)){throw 'Duplicate or overlapping expanded profile operation; flatten the profile first.'};$seen[$selection.Id]=$selection
  }
  $visiting=@{};$done=@{}
  function Add-PackageRequirement {
    param([string]$Id,[string]$Variant,[string]$Origin,[bool]$Prerequisite,[int]$Depth)
    if($Depth -gt 128 -or $visiting.ContainsKey($Id)){throw 'Cyclic or excessive catalog prerequisite graph.'}
    if(-not $ops.ContainsKey($Id) -or $ops[$Id].Kind -ne 'Package'){throw 'Unknown or non-package catalog prerequisite.'}
    $op=$ops[$Id]
    if($seen.ContainsKey($Id)){
      if($seen[$Id].State -eq 'Absent'){$issues.Add([pscustomobject]@{Id=$Id;Reason='PrerequisiteSelectedAbsent'});return}
      $Variant=[string]$seen[$Id].Variant
    }
    if($op.Variants -and -not $Variant){$issues.Add([pscustomobject]@{Id=$Id;Reason='ExplicitVariantRequired'});return}
    $resolved=Resolve-RidePackageSelection -Operation $op -Variant $Variant -MetadataOnly -IgnorePreferences
    $key=$Id+'|'+$resolved.SelectedVariant
    if($done.ContainsKey($key)){return}
    $visiting[$Id]=$true
    if($resolved.PrerequisitePackageId){Add-PackageRequirement -Id $resolved.PrerequisitePackageId -Origin $Id -Prerequisite $true -Depth ($Depth+1)}
    $visiting.Remove($Id);$done[$key]=$true
    $requirements.Add([pscustomobject]@{Operation=$resolved;Id=$Id;Variant=$resolved.SelectedVariant;Origin=$Origin;CatalogPrerequisite=$Prerequisite;ExplicitlySelected=$seen.ContainsKey($Id)})
  }
  foreach($selection in $expanded){
    $op=$ops[$selection.Id]
    if($op.Kind -eq 'Package'){
      if($selection.State -notin @('Present','Absent')){throw 'Package selection requires Present or Absent.'}
      if($selection.State -eq 'Present'){Add-PackageRequirement -Id $op.Id -Variant $selection.Variant -Origin $selection.Origin -Prerequisite $false -Depth 0}
      else{$other.Add([pscustomobject]@{Id=$op.Id;Kind=$op.Kind;State='Absent';Reason='RemovalAndRecoverySourceUnverified'})}
    }else{
      if($selection.ContainsKey('Variant')){throw 'Variant requires a package.'}
      $state=$selection.State
      if($state -eq 'Baseline' -and $op.Kind -in @('RegistryValue','RegistryValueSet','ShellFolder','ProfileSetting')){$state=$op.BaselineState}
      if($op.States -isnot [hashtable] -or -not $op.States.ContainsKey($state)){throw 'Unsupported non-package selection state.'}
      $other.Add([pscustomobject]@{Id=$op.Id;Kind=$op.Kind;State=$state;Reason='NonPackageSourceRequirementsUnverified'})
    }
  }
  $artifactIds=@{};$walking=@{}
  function Visit-SelectedArtifact {
    param([string]$Id,[int]$Depth)
    if($Depth -gt 128 -or $walking.ContainsKey($Id)){throw 'Cyclic or excessive manifest dependency graph.'}
    if($artifactIds.ContainsKey($Id)){return};$walking[$Id]=$true
    foreach($dep in $index.Artifacts[$Id].DependencyIds){Visit-SelectedArtifact $dep ($Depth+1)}
    $walking.Remove($Id);$artifactIds[$Id]=$true
  }
  foreach($id in $selected.ArtifactIds){Visit-SelectedArtifact $id 0}
  $rows=@(foreach($requirement in $requirements){
    $op=$requirement.Operation
    $matches=@(foreach($id in $artifactIds.get_Keys()){$a=$index.Artifacts[$id];if($a.PackageId -ieq $op.Id -and $a.Variant -ieq $requirement.Variant){$a}})
    $status='Declared';$artifactId=$null;$downloadComparison='NotCompared'
    if($matches.Count -eq 0){$status='MissingSelectedArtifact'}
    elseif($matches.Count -gt 1){$status='AmbiguousSelectedArtifact'}
    else{
      $a=$matches[0];$artifactId=$a.Id
      $downloadComparison=if(-not $op.DownloadUri){'NotDeclared'}elseif([string]$op.DownloadUri -ceq [string]$a.DownloadUri){'Matched'}else{'Mismatch'}
      if($a.Status -cne 'Included'){$status='SelectedArtifactOmitted'}
      elseif($op.PackageVersion -and $op.PackageVersion -cne $a.Version){$status='CatalogVersionMismatch'}
      elseif($op.Architecture -and $op.Architecture -ine $a.Architecture){$status='CatalogArchitectureMismatch'}
      elseif($downloadComparison -ceq 'Mismatch'){$status='CatalogDownloadUriMismatch'}
      else{
        foreach($field in @('ProductUri','License','LicenseUri','TermsUri')){if([string]$op[$field] -cne [string]$a.$field){$status='CatalogPublisherMetadataMismatch';break}}
        if($status -eq 'Declared' -and $op.ExpectedSha256){
          $payloads=@($a.FileIds|ForEach-Object {$index.Files[$_]}|Where-Object Role -ceq Payload)
          if($payloads.Count -ne 1 -or $payloads[0].Sha256 -ine $op.ExpectedSha256){$status='CatalogDigestMismatch'}
        }
      }
    }
    if($status -cne 'Declared'){$issues.Add([pscustomobject]@{Id=$op.Id;Reason=$status})}
    [pscustomobject]@{Id=$op.Id;Variant=$requirement.Variant;Origin=$requirement.Origin;CatalogPrerequisite=$requirement.CatalogPrerequisite;ExplicitlySelected=$requirement.ExplicitlySelected;ArtifactId=$artifactId;Status=$status;CatalogTargetDeclared=($selected.Target -in $op.SupportedTargets);PendingAcceptance=[bool]$op.PendingAcceptance;CatalogDownloadUriComparison=$downloadComparison;DownloadSourceVerified=$false}
  })
  [pscustomobject]@{
    SchemaVersion=1;Kind='RideOfflineProfileCoverage';ProducerVersion='0.6.0';ProfileId=$selected.Id;ProfileName=$Profile.Name
    CatalogFileId=$CatalogFileId;CatalogSha256=$CatalogSha256.ToLowerInvariant();ProfileSha256=$ProfileSha256.ToLowerInvariant()
    PackageRequirements=$rows;CoverageIssues=$issues.ToArray();OtherSelections=$other.ToArray()
    SelectedPackageDeclarationsComplete=($issues.Count -eq 0);SourceHashClaimsMatchManifest=$true;ParsedBytesBindingVerified=$false
    FileIntegrityVerified=$false;InstallerDependencyClosureVerified=$false;NonPackageSourceCoverageVerified=$false
    ActualTargetVerified=$false;NetworkFallbackAllowed=$false;ReadyForMutation=$false;RecoverySupported=$false
  }
}
function Assert-RideAssemblyLocalPath {
  param([string]$Path,[switch]$Directory)
  if($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '[*?"<>|\x00-\x1f]' -or $Path.Substring(2).Contains(':') -or $Path -match '(^|[\\/])\.\.?([\\/]|$)'){throw 'Assembly paths must be explicit local drive paths without traversal or alternate streams.'}
  $full=[IO.Path]::GetFullPath($Path).TrimEnd('\','/')
  if($full.Length -eq 2){$full+='\'}
  $attributes=Get-RideBundlePathAttributes $full
  if($Directory -and ($attributes -band [IO.FileAttributes]::Directory) -eq 0){throw 'Assembly parent must be an existing directory.'}
  if(-not $Directory -and ($attributes -band [IO.FileAttributes]::Directory) -ne 0){throw 'Assembly sources must be regular files.'}
  $ancestor=$full
  while($ancestor){if(((Get-RideBundlePathAttributes $ancestor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Assembly path ancestry contains a reparse point.'};$ancestor=[IO.Path]::GetDirectoryName($ancestor)}
  $full
}

function Copy-RideAssemblyFile {
  param([string]$Source,[string]$Destination,$File)
  $sourcePath=Assert-RideAssemblyLocalPath $Source
  $inputStream=Open-RideBundleReadStream $sourcePath;$outputStream=$null;$algorithm=$null
  try{
    if($inputStream.Length -ne $File.Length){throw 'Assembly source length does not match the manifest.'}
    $outputStream=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $algorithm=[Security.Cryptography.SHA256]::Create();$buffer=[byte[]]::new(1MB);[long]$copied=0
    while(($read=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0){
      if($read -gt $File.Length-$copied){throw 'Assembly source grew beyond the declared bound.'}
      $outputStream.Write($buffer,0,$read);$null=$algorithm.TransformBlock($buffer,0,$read,$buffer,0);$copied+=$read
    }
    $null=$algorithm.TransformFinalBlock([byte[]]::new(0),0,0)
    $sha256=([BitConverter]::ToString($algorithm.Hash)).Replace('-','').ToLowerInvariant()
    if($copied -ne $File.Length -or $sha256 -ine $File.Sha256){throw 'Assembly source digest or length does not match the manifest.'}
    $outputStream.Flush($true)
  }finally{if($algorithm){$algorithm.Dispose()};if($outputStream){$outputStream.Dispose()};$inputStream.Dispose()}
}

function New-RideOfflineBundle {
  <#
  .SYNOPSIS
    Copy explicitly mapped local files into a new retained offline bundle version.
  .DESCRIPTION
    Validates manifest structure and source mappings before ShouldProcess. Copies
    to a uniquely named sibling staging directory using exclusive output files,
    checks every copied file against its declared length/hash, rechecks the entire
    staged set after the last copy, writes the manifest,
    then moves the completed directory to a previously absent destination. Does
    not download, install, prune, replace an older bundle or approve redistribution.
  .PARAMETER Manifest
    Schema-1 RideOfflineBundle manifest with exact file hashes and omission records.
    Engine commit provenance and complete installer dependencies remain unverified.
  .PARAMETER SourceFiles
    Hashtable mapping every manifest File Id to one explicit local source file.
    No extra/missing mappings, UNC paths, reparse ancestry or automatic discovery.
    These local source paths are never copied into the transferable manifest.
  .PARAMETER DestinationPath
    New local bundle directory under an existing parent. Existing destinations,
    including empty directories, are refused. Parent directories are not created.
  .PARAMETER MaximumBytes
    Bound for all manifest files, default 128 GiB, maximum 1 TiB.
  .PARAMETER CoverageProfileId
    Optional manifest profile IDs whose package content must pass byte-bound
    coverage before completion. Requires CatalogFileId. Unselected omissions stay
    explicit and do not block these selected profiles. Preview performs no coverage.
  .PARAMETER CatalogFileId
    Engine file ID containing the pinned catalog for CoverageProfileId. Both
    parameters must be supplied together. No bundled script or installer is run.
  .EXAMPLE
    New-RideOfflineBundle -Manifest $manifest -SourceFiles $sources -DestinationPath C:\Offline\bundle-v2 -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Preview, Completed or Failed status, staging/destination paths,
    verified file IDs and recovery instructions. Failed staging is retained.
  .NOTES
    Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
    Requires read access to sources and write access to the existing parent.
    No elevation, installer, source acquisition, external publication or target
    configuration. Completion verifies copied bytes, not air-gap readiness.
    Recovery: inspect a reported failed staging directory, correct sources, and
    retry into a fresh destination. No automatic resume, deletion or replacement.
    Keep prior bundle versions until the operator explicitly removes them.
  #>
  [CmdletBinding(SupportsShouldProcess,ConfirmImpact='Medium')]
  param(
    [Parameter(Mandatory)]$Manifest,
    [Parameter(Mandatory)][hashtable]$SourceFiles,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DestinationPath,
    [ValidateRange(1,1099511627776)][long]$MaximumBytes=137438953472,
    [ArgumentCompleter({param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $attribute=(Get-Command Test-RideOfflineProfileCoverage).Parameters['ProfileId'].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
        & $attribute.ScriptBlock $commandName $parameterName $wordToComplete $commandAst $fakeBoundParameters
      }catch{}
    })][string[]]$CoverageProfileId=@(),
    [ArgumentCompleter({param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $attribute=(Get-Command Test-RideOfflineProfileCoverage).Parameters['CatalogFileId'].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
        & $attribute.ScriptBlock $commandName $parameterName $wordToComplete $commandAst $fakeBoundParameters
      }catch{}
    })][string]$CatalogFileId
  )
  $index=Read-RideBundleIndex $Manifest
  $coverageIds=Get-RideBundleIds $CoverageProfileId
  if([bool]$coverageIds.Count -ne [bool]$CatalogFileId){throw 'CoverageProfileId and CatalogFileId must be supplied together.'}
  if($CatalogFileId){
    if($CatalogFileId -notin $index.EngineFileIds -or $index.Files[$CatalogFileId].Length -gt 2MB){throw 'Coverage catalog must be an Engine file no larger than 2 MiB.'}
    foreach($id in $coverageIds){
      if(-not $index.Profiles.ContainsKey($id) -or $index.Files[$index.Profiles[$id].FileId].Length -gt 64KB){throw 'Coverage requires known profiles no larger than 64 KiB.'}
    }
  }
  if($SourceFiles.get_Count() -ne $index.Files.get_Count()){throw 'Source mapping must include exactly every manifest file.'}
  $referenced=@{}
  foreach($id in $index.EngineFileIds){$referenced[$id]=$true}
  foreach($p in $index.Profiles.get_Values()){$referenced[$p.FileId]=$true}
  foreach($a in @($index.Artifacts.get_Values())+@($index.Servicing.get_Values())){foreach($id in $a.FileIds){$referenced[$id]=$true}}
  [long]$total=0;$sources=@{}
  foreach($file in $index.Files.get_Values()){
    if(-not $referenced.ContainsKey($file.Id)){throw 'Assembly refuses unreferenced manifest files.'}
    if($file.RelativePath -match '^(?i:manifest\.json|assembly\.json)(/|$)'){throw 'Manifest file path collides with reserved assembly metadata.'}
    if(-not $SourceFiles.ContainsKey($file.Id) -or $SourceFiles[$file.Id] -isnot [string]){throw 'Missing or invalid local source mapping.'}
    if($file.Length -gt $MaximumBytes-$total){throw 'Entire bundle exceeds the explicit byte bound.'};$total+=$file.Length
    $sources[$file.Id]=Assert-RideAssemblyLocalPath $SourceFiles[$file.Id]
  }
  if($DestinationPath -notmatch '^[A-Za-z]:[\\/]' -or $DestinationPath -match '[*?"<>|\x00-\x1f]' -or $DestinationPath.Substring(2).Contains(':') -or $DestinationPath -match '(^|[\\/])\.\.?([\\/]|$)'){throw 'Invalid local bundle destination.'}
  $destination=[IO.Path]::GetFullPath($DestinationPath).TrimEnd('\','/')
  $name=[IO.Path]::GetFileName($destination);Assert-RideBundleRelativePath $name
  $parent=Assert-RideAssemblyLocalPath ([IO.Path]::GetDirectoryName($destination)) -Directory
  if(Test-Path -LiteralPath $destination){throw 'Bundle destination already exists; choose a new version directory.'}
  $manifestBytes=[Text.UTF8Encoding]::new($false).GetBytes(($Manifest|ConvertTo-Json -Depth 20)+"`n")
  if($manifestBytes.Length -gt 4MB){throw 'Serialized manifest exceeds 4 MiB.'}
  $result=[pscustomobject]@{
    SchemaVersion=1;Kind='RideOfflineBundleAssembly';ProducerVersion='0.7.0';Status='Preview'
    BundleId=$Manifest.BundleId;BundleVersion=$Manifest.BundleVersion;DestinationPath=$destination
    StagingPath=$null;DeclaredBytes=$total;VerifiedFileIds=@();ErrorType=$null;FailureStage=$null;FailedFileId=$null
    CatalogFileId=$CatalogFileId;CoverageProfileIds=$coverageIds;CoverageStatus=$(if($CatalogFileId){'Pending'}else{'NotRequested'});CoverageReports=@();FailedProfileId=$null
    DeclaredOmissions=@(@($index.Artifacts.get_Values())+@($index.Servicing.get_Values())|Where-Object Status -ceq Omitted|ForEach-Object {[pscustomobject]@{Id=$_.Id;Reason=$_.OmissionCode}})
    ReadyForMutation=$false;EngineSourceCommitVerified=$false;RedistributionApproved=$false
    Recovery='Retain prior versions. On failure inspect reported staging content; retry with corrected sources into a fresh destination. No automatic deletion or resume.'
  }
  if(-not $PSCmdlet.ShouldProcess($destination,'Assemble a new local bundle from explicitly mapped and verified files')){return $result}
  $stage=Join-Path $parent ('.ride-staging-'+[guid]::NewGuid().ToString('N'))
  $verified=[Collections.Generic.List[string]]::new()
  $phase='CreateStage';$currentFileId=$null
  try{
    $null=Assert-RideAssemblyLocalPath $parent -Directory
    $null=New-Item -ItemType Directory -Path $stage -ErrorAction Stop
    $result.StagingPath=$stage
    foreach($id in @($index.Files.get_Keys()|Sort-Object)){
      $phase='CopyAndVerifyFile';$currentFileId=$id
      $file=$index.Files[$id];$target=Join-Path $stage $file.RelativePath
      $directory=[IO.Path]::GetDirectoryName($target)
      $null=[IO.Directory]::CreateDirectory($directory)
      $null=Assert-RideAssemblyLocalPath $directory -Directory
      Copy-RideAssemblyFile -Source $sources[$id] -Destination $target -File $file
      $observed=Get-RideBundleFileObservation -Root $stage -File $file
      if($observed.Status -cne 'Verified'){throw 'Staged output verification failed.'}
      $verified.Add($id)
    }
    if($CatalogFileId){
      $phase='CheckProfileCoverage';$currentFileId=$null
      foreach($id in $coverageIds){
        $result.FailedProfileId=$id
        $coverage=Test-RideOfflineBundle -Manifest $Manifest -Root $stage -ProfileId $id -CatalogFileId $CatalogFileId -MaximumBytes $MaximumBytes
        $result.CoverageReports+=@($coverage)
        if(-not $coverage.SelectedPackageContentComplete){throw 'Selected profile package content is incomplete.'}
      }
      $result.CoverageStatus='Passed';$result.FailedProfileId=$null
    }
    $phase='ReverifyStagedFiles';$verified.Clear()
    foreach($id in @($index.Files.get_Keys()|Sort-Object)){
      $currentFileId=$id
      $observed=Get-RideBundleFileObservation -Root $stage -File $index.Files[$id]
      if($observed.Status -cne 'Verified'){throw 'Staged content changed after its initial verification.'}
      $verified.Add($id)
    }
    $phase='WriteManifest';$currentFileId=$null
    $stream=[IO.File]::Open((Join-Path $stage 'manifest.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($manifestBytes,0,$manifestBytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $record=[ordered]@{SchemaVersion=1;Kind='RideOfflineBundleAssemblyRecord';Status='Complete';BundleId=$Manifest.BundleId;BundleVersion=$Manifest.BundleVersion;VerifiedFileIds=$verified.ToArray();CatalogFileId=$CatalogFileId;CoverageProfileIds=$coverageIds;CoverageStatus=$result.CoverageStatus;CompletedAtUtc=[DateTime]::UtcNow.ToString('o');ReadyForMutation=$false;EngineSourceCommitVerified=$false}
    $recordBytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 6)+"`n")
    $stream=[IO.File]::Open((Join-Path $stage 'assembly.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($recordBytes,0,$recordBytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $null=Assert-RideAssemblyLocalPath $parent -Directory
    $phase='CommitDirectory'
    [IO.Directory]::Move($stage,$destination)
    $result.Status='Completed';$result.StagingPath=$null
  }catch{
    $result.Status='Failed';$result.ErrorType=$_.Exception.GetType().FullName;$result.FailureStage=$phase;$result.FailedFileId=$currentFileId
    if($phase -eq 'CheckProfileCoverage'){$result.CoverageStatus='Failed'}
    Write-Verbose 'Assembly failed; any reported staging content is retained and no prior bundle was replaced.'
  }
  $result.VerifiedFileIds=$verified.ToArray()
  $result
}
Export-ModuleMember -Function Test-RideOfflineBundle, Test-RideOfflineProfileCoverage, New-RideOfflineBundle
