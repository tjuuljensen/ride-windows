<#
.SYNOPSIS
  Resolve the fixed reviewed portable-package acceptance selection.
.DESCRIPTION
  Reads catalog data and the retained PSScriptTools member review. No acquisition,
  handler or VM calls occur.
  NirSoft and other collections are outside this fixed acceptance selection.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Author: RIDE-Windows maintainers. Version: 0.9.0.
  Changelog: 0.9.0: Add the nine individually pinned Sysinternals product lifecycle selection.
    0.8.0: Add the pinned ImageMagick portable Q16 lifecycle selection.
    0.7.0: Add the exact Sysinternals Suite snapshot file-lifecycle case.
    0.6.0: Add the three pinned MiTeC utility file-lifecycle cases.
    0.5.0: Add an isolated MiTeC SQLite Query file-lifecycle batch.
    0.4.0: Add the pinned 4GB Patch candidate to NTCore file staging.
    0.3.0: Read member evidence from the registered source snapshot.
    0.2.0: Add explicit PSScriptTools and offline Caffeine selections.
    0.1.0: Bind MiTeC and NTCore acceptance to reviewed portable metadata.
#>
function Get-RidePortableAcceptanceCases {
  <#
  .SYNOPSIS
    Return exact package/variant pairs for the selected acceptance batch.
  .PARAMETER Catalog
    Parsed RIDE catalog; no handler imports or live inspection are performed.
  .PARAMETER Batch
    Explicit focused batch; AllReviewed selects viewer architectures and all fixed NTCore candidates.
  .PARAMETER ReviewRoot
    Source snapshot root containing retained member-review evidence.
  .EXAMPLE
    Get-RidePortableAcceptanceCases -Catalog $catalog -Batch MiTeCViewers
  .OUTPUTS
    Objects with Id, Variant and the resolved declarative Operation.
  .NOTES
    Refuses missing, unpinned or non-portable candidates before runtime work.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable]$Catalog,
    [ValidateSet('MiTeCViewers','NTCore','AllReviewed','PSScriptTools','OfflineCaffeine','SQLiteQuery','MiTeCUtilityFiles','SysinternalsSuite','SysinternalsProducts','ImageMagick')][string]$Batch='AllReviewed',
    [string]$ReviewRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
  $groups=@{
    MiTeCViewers=@('package.mitec-json-viewer','package.mitec-xml-viewer')
    NTCore=@('package.ntcore-pe-detective','package.ntcore-cff-explorer','package.ntcore-4gb-patch')
    PSScriptTools=@('package.psscripttools')
    OfflineCaffeine=@('package.caffeine')
    SQLiteQuery=@('package.mitec-sqlite-query')
    MiTeCUtilityFiles=@('package.mitec-uuid-generator','package.mitec-certificate-generator','package.mitec-certificate-information')
    SysinternalsSuite=@('package.sysinternals-suite')
    SysinternalsProducts=@('package.sysinternals-process-explorer','package.sysinternals-autoruns','package.sysinternals-tcpview','package.sysinternals-procmon','package.sysinternals-rammap','package.sysinternals-disk2vhd','package.sysinternals-sigcheck','package.sysinternals-strings','package.sysinternals-handle')
    ImageMagick=@('package.imagemagick-portable-q16')
  }
  $ids=if($Batch -eq 'AllReviewed'){@($groups.MiTeCViewers)+@($groups.NTCore)}else{@($groups[$Batch])}
  foreach($id in $ids){
    $matches=@($Catalog.Operations|Where-Object Id -ceq $id)
    if($matches.Count -ne 1){throw "Acceptance requires exactly one declared package: $id"}
    $base=$matches[0]
    $variants=if($id -in $groups.MiTeCViewers){@('portable','portable-x86')}else{@('portable')}
    foreach($variant in $variants){
      if(-not $base.Variants.ContainsKey($variant)){throw "Missing reviewed variant: $id / $variant"}
      $op=$base.Clone()
      foreach($key in $base.Variants[$variant].Keys){$op[$key]=$base.Variants[$variant][$key]}
      $archiveAccepted=($op.PortableFormat -eq 'Zip' -and $op.AssetName -match '^[a-zA-Z0-9_.-]+\.zip$') -or
        ($Batch -eq 'ImageMagick' -and $id -ceq 'package.imagemagick-portable-q16' -and $op.PortableFormat -eq 'SevenZip' -and $op.AssetName -match '^[a-zA-Z0-9_.-]+\.7z$')
      $prerequisiteAccepted=-not $op.PrerequisitePackageId -or
        ($Batch -eq 'ImageMagick' -and $id -ceq 'package.imagemagick-portable-q16' -and $op.PrerequisitePackageId -ceq 'package.vcredist-v14-x64')
      if($op.Kind -ne 'Package' -or $op.Handler -ne 'Package' -or $op.InstallerType -ne 'Portable' -or
         -not $archiveAccepted -or $op.DownloadProvider -ne 'DirectHttps' -or
         $op.ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$' -or
         $op.Scope -ne 'Machine' -or -not $op.RequiresAdmin -or -not $prerequisiteAccepted -or $op.DependsOn -or
         ('Windows 11' -notin $op.CandidateTargets -and 'Windows 11' -notin $op.SupportedTargets) -or -not $op.RequiredFiles.Count){throw "Unreviewed acceptance metadata: $id / $variant"}
      $members=@(if($op.PortableMembers){$op.PortableMembers}else{$op.RequiredFiles})
      if($id -eq 'package.psscripttools'){
        $review=Get-Content -LiteralPath (Join-Path $ReviewRoot 'docs/archive/evidence/psscripttools-source-review-2026-10-17.json') -Raw|ConvertFrom-Json
        if($review.Sha256 -cne $op.ExpectedSha256 -or $review.FileCount -ne 360){throw 'PSScriptTools member review does not match the catalog pin.'}
        $members=@($review.Members|Where-Object {-not $_.Path.EndsWith('/')}|ForEach-Object Path)
        if($members.Count -ne 360){throw 'Incomplete PSScriptTools member review.'}
      }
      [pscustomobject]@{Id=$id;Variant=$variant;Operation=$op;ExpectedFiles=$members}
    }
  }
}
function Get-RidePortableAcceptancePayloads {
  <#
  .SYNOPSIS
    Validate the exact retained archive selection before VM access.
  .DESCRIPTION
    Rejects extra IDs before reading payload paths; verifies catalog pins and
    rejects reparse points. Returns only explicitly selected reviewed archives.
  .PARAMETER Cases
    Fixed cases from Get-RidePortableAcceptanceCases.
  .PARAMETER ManifestPath
    Local JSON array containing one Id and Path per selected package.
  .EXAMPLE
    Get-RidePortableAcceptancePayloads -Cases $cases -ManifestPath .\payloads.json
  .OUTPUTS
    Id, Path, FileName and Sha256 for verified local archives.
  .NOTES
    Reads archives without extracting or executing any payload.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][object[]]$Cases,[Parameter(Mandatory)][string]$ManifestPath)
  $manifest=Get-Item -LiteralPath $ManifestPath -ErrorAction Stop
  if($manifest.PSIsContainer -or $manifest.Length -gt 65536){throw 'Invalid archive manifest.'}
  $rows=Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop|ConvertFrom-Json
  $rows=@($rows)
  $ids=@($Cases.Id|Sort-Object -Unique)
  if($rows.Count -ne $ids.Count -or @($rows.Id|Sort-Object -Unique).Count -ne $ids.Count -or @($rows|Where-Object Id -cnotin $ids).Count){throw 'Manifest must contain exactly the selected reviewed package IDs.'}
  foreach($id in $ids){
    $row=@($rows|Where-Object Id -ceq $id)[0]
    $op=($Cases|Where-Object Id -ceq $id|Select-Object -First 1).Operation
    $extension=[IO.Path]::GetExtension([string]$op.AssetName)
    if(-not $row.Path -or [IO.Path]::GetExtension($row.Path) -ine $extension -or $extension -notin @('.zip','.7z') -or
       ($extension -eq '.7z' -and ($op.Id -cne 'package.imagemagick-portable-q16' -or $op.PortableFormat -ne 'SevenZip'))){throw 'Archive extension does not match an explicitly reviewed portable selection.'}
    $file=Get-Item -LiteralPath $row.Path -ErrorAction Stop
    $ancestor=$file
    while($ancestor){
      if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Archive paths must not traverse reparse points.'}
      $ancestor=if($ancestor.PSIsContainer){$ancestor.Parent}else{$ancestor.Directory}
    }
    if($file.PSIsContainer -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ine $op.ExpectedSha256){throw "Retained archive digest mismatch: $id"}
    [pscustomobject]@{Id=$id;Path=$file.FullName;FileName=$op.AssetName;Sha256=$op.ExpectedSha256}
  }
}
Export-ModuleMember -Function Get-RidePortableAcceptanceCases,Get-RidePortableAcceptancePayloads
