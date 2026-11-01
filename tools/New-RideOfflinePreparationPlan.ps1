<#
.SYNOPSIS
  Build a read-only local package preparation plan for an offline RIDE bundle.
.DESCRIPTION
  Expands explicit profile selections or the target-scoped full package set,
  closes catalog prerequisites, and compares retained artifact observations with
  files under caller-supplied cache roots. It never downloads, extracts, installs,
  queries Windows state, or writes an output file.
.PARAMETER Mode
  ProfileSelected uses the supplied ProfilePath files. FullSet lists every package
  variant applicable to the explicit target matrix.
.PARAMETER TargetMatrixPath
  UTF-8 JSON array of target records with Id, Name, Build, EditionId and Architecture.
.PARAMETER ProfilePath
  One or more schema-1 profile PSD1 files. Required only for ProfileSelected.
.PARAMETER ArtifactObservationsPath
  Optional retained acquisition-observation JSON array. Defaults to the repository
  catalog observations file; no remote lookup is performed.
.PARAMETER CacheRoot
  Explicit local roots to inspect for package bytes. No implicit cache is searched.
.PARAMETER VersionSelectionsPath
  Optional UTF-8 JSON object keyed by PackageId|Variant or OperationId|Variant.
.PARAMETER LicenseReviewStatusesPath
  Optional local JSON object keyed by PackageId; status is informational only.
.EXAMPLE
  .\tools\New-RideOfflinePreparationPlan.ps1 -Mode ProfileSelected -TargetMatrixPath .\targets.json -ProfilePath .\profiles\default.psd1 -CacheRoot 'D:\RIDE-cache'
.EXAMPLE
  .\tools\New-RideOfflinePreparationPlan.ps1 -Mode FullSet -TargetMatrixPath .\targets.json | ConvertTo-Json -Depth 12
.INPUTS
  None.
.OUTPUTS
  PSCustomObject. Local payload and independent target-acceptance statuses.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Read-only; no elevation. Output may contain local cache paths. It does not
  assemble a bundle or establish target acceptance, redistribution approval or
  disconnected installation readiness.
  Version: 0.1.0.
  Changelog: 0.1.0: Add explicit-input read-only package preparation planning.
.LINK
  ../docs/offline-bundles.md
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('ProfileSelected','FullSet')][string]$Mode,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TargetMatrixPath,
  [string[]]$ProfilePath=@(),
  [string]$ArtifactObservationsPath,
  [string[]]$CacheRoot=@(),
  [string]$VersionSelectionsPath,
  [string]$LicenseReviewStatusesPath
)
$ErrorActionPreference='Stop'

function Read-PlanJson {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][int]$MaximumBytes)
  $file=Get-Item -LiteralPath $Path -ErrorAction Stop
  if($file -isnot [IO.FileInfo] -or $file.Length -gt $MaximumBytes -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'JSON input must be a regular file within its size limit.'}
  $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{
    if($stream.Length -gt $MaximumBytes){throw 'JSON input exceeds its size limit.'}
    $bytes=[byte[]]::new([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$read=$stream.Read($bytes,$offset,$bytes.Length-$offset);if(-not $read){throw 'Incomplete JSON read.'};$offset+=$read}
  }finally{$stream.Dispose()}
  try{[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)|ConvertFrom-Json -ErrorAction Stop}catch{throw 'Input is not valid UTF-8 JSON.'}
}

function ConvertTo-PlanHashtable {
  param([Parameter(Mandatory)][object]$Value)
  if($Value -is [pscustomobject]){
    $result=@{}
    foreach($property in $Value.PSObject.Properties){$result[$property.Name]=ConvertTo-PlanValue $property.Value}
    return ,$result
  }
  ConvertTo-PlanValue $Value
}

function ConvertTo-PlanValue {
  param([AllowNull()][object]$Value)
  if($null -eq $Value){return $null}
  if($Value -is [pscustomobject]){return ConvertTo-PlanHashtable $Value}
  if($Value -is [System.Collections.IDictionary]){return $Value}
  if($Value -is [array]){return ,@($Value|ForEach-Object {ConvertTo-PlanValue $_})}
  return $Value
}

if($Mode -eq 'ProfileSelected' -and -not $ProfilePath.Count){throw 'ProfileSelected mode requires at least one ProfilePath.'}
if($Mode -eq 'FullSet' -and $ProfilePath.Count){throw 'FullSet mode does not accept ProfilePath.'}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$catalogPath=Join-Path $repositoryRoot 'catalog/operations.psd1'
$catalogReader=Join-Path $repositoryRoot 'modules/RIDE.CatalogData.psm1'
$offlineModule=Join-Path $repositoryRoot 'modules/RIDE.OfflineBundle.psm1'
Import-Module $catalogReader -Force -ErrorAction Stop
Import-Module $offlineModule -Force -ErrorAction Stop
$catalog=Import-RideCatalogData -Path $catalogPath
$targets=@(Read-PlanJson -Path $TargetMatrixPath -MaximumBytes 1MB|ForEach-Object {ConvertTo-PlanHashtable $_})
if(-not $ArtifactObservationsPath){$ArtifactObservationsPath=Join-Path $repositoryRoot 'catalog/artifact-observations.json'}
$observationDocument=Read-PlanJson -Path $ArtifactObservationsPath -MaximumBytes 4MB
if($observationDocument.SchemaVersion -ne 1 -or $null -eq $observationDocument.Observations -or @($observationDocument.Observations).Count -gt 32768){throw 'Artifact observations must be a bounded schema-1 document.'}
$observations=@($observationDocument.Observations)
$profiles=[Collections.Generic.List[hashtable]]::new()
foreach($path in $ProfilePath){
  $file=Get-Item -LiteralPath $path -ErrorAction Stop
  if($file -isnot [IO.FileInfo] -or $file.Length -gt 256KB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Profile input must be a regular PSD1 file no larger than 256 KiB.'}
  $data=Import-PowerShellDataFile -LiteralPath $file.FullName -ErrorAction Stop
  if($data -isnot [hashtable]){throw 'Profile input must contain a root data hashtable.'}
  $profiles.Add(@{Id=[IO.Path]::GetFileNameWithoutExtension($file.Name);Data=$data})
}
$versions=@{}
if($VersionSelectionsPath){$versions=ConvertTo-PlanHashtable (Read-PlanJson -Path $VersionSelectionsPath -MaximumBytes 1MB);if($versions -isnot [hashtable]){throw 'Version selections must be a JSON object.'}}
$licenseStatuses=@{}
if($LicenseReviewStatusesPath){$licenseStatuses=ConvertTo-PlanHashtable (Read-PlanJson -Path $LicenseReviewStatusesPath -MaximumBytes 1MB);if($licenseStatuses -isnot [hashtable]){throw 'License review statuses must be a JSON object.'}}
New-RideOfflinePreparationPlan -Mode $Mode -Catalog $catalog -Targets $targets -Profiles @($profiles.ToArray()) -ArtifactObservations $observations -CacheRoots $CacheRoot -VersionSelections $versions -LicenseReviewStatuses $licenseStatuses
