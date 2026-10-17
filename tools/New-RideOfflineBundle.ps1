<#
.SYNOPSIS
  Assemble a new local offline bundle from prepared files and reviewed metadata.
.DESCRIPTION
  Reads bounded manifest/source-map JSON and copies only explicitly mapped files.
  New files are verified individually and again as a complete staged set before
  metadata is written and the directory moves to a previously absent destination.
  Failed staging and older versions are retained.
  No downloads, installer execution, host setup, deletion or external publication.
.PARAMETER ManifestPath
  Existing UTF-8 schema-1 RideOfflineBundle JSON, at most 4 MiB.
.PARAMETER SourceMapPath
  Existing UTF-8 JSON object mapping every manifest File Id to a local absolute
  file path, at most 4 MiB. Paths are used only for local reads and are not bundled.
.PARAMETER DestinationPath
  New local drive directory beneath an existing parent. Existing paths are refused.
.PARAMETER MaximumBytes
  Maximum total declared content, default 128 GiB and maximum 1 TiB.
.PARAMETER CoverageProfileId
  Optional manifest profile IDs requiring package-content coverage before completion.
  Supply CatalogFileId as well. WhatIf validates IDs but does not claim coverage.
.PARAMETER CatalogFileId
  Manifest Engine file ID for the pinned catalog. Requires CoverageProfileId.
  Coverage reads staged declarative data without executing bundled code.
.EXAMPLE
  .\tools\New-RideOfflineBundle.ps1 -ManifestPath C:\Preparation\manifest.json -SourceMapPath C:\Preparation\sources.json -DestinationPath C:\Offline\bundle-v2 -WhatIf
.EXAMPLE
  $result = .\tools\New-RideOfflineBundle.ps1 -ManifestPath C:\Preparation\manifest.json -SourceMapPath C:\Preparation\sources.json -DestinationPath C:\Offline\bundle-v2
  $result | Format-List
.INPUTS
  None.
.OUTPUTS
  PSCustomObject. Preview/Completed/Failed, retained staging path and failure phase.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Explicit prepared source metadata; read access to inputs and write
  access to the destination parent. No elevation is requested. Check Status;
  Failed is a recoverable assembly result, not a completed bundle.
  Recovery: Preserve the reported staging directory and previous bundle versions.
  Correct inputs and retry using a new destination. No automatic resume or cleanup.
  Copied hashes do not prove complete engine source, publisher authenticity,
  redistribution approval, native offline behavior or permission to install.
  Version: 0.3.0.
  Changelog: 0.3.0: Add optional selected-profile package coverage before completion.
    0.2.0: Reverify staged files after all copies and before commit metadata.
    0.1.0: Add explicit-source, non-replacing local bundle assembly.
.LINK
  ../docs/offline-bundles.md
#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='Medium')]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ManifestPath,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SourceMapPath,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DestinationPath,
  [ValidateRange(1,1099511627776)][long]$MaximumBytes=137438953472,
  [ArgumentCompleter({param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{
      $tool=Join-Path (Split-Path -Parent (Get-Command $commandName -ErrorAction Stop).Path) 'Test-RideOfflineBundle.ps1'
      $attribute=(Get-Command $tool -ErrorAction Stop).Parameters['ProfileId'].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
      & $attribute.ScriptBlock $commandName $parameterName $wordToComplete $commandAst $fakeBoundParameters
    }catch{}
  })][string[]]$CoverageProfileId=@(),
  [ArgumentCompleter({param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{
      $tool=Join-Path (Split-Path -Parent (Get-Command $commandName -ErrorAction Stop).Path) 'Test-RideOfflineBundle.ps1'
      $attribute=(Get-Command $tool -ErrorAction Stop).Parameters['CatalogFileId'].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
      & $attribute.ScriptBlock $commandName $parameterName $wordToComplete $commandAst $fakeBoundParameters
    }catch{}
  })][string]$CatalogFileId
)
$ErrorActionPreference='Stop'
function Read-AssemblyJson {
  param([string]$Path)
  $file=Get-Item -LiteralPath $Path -ErrorAction Stop
  if($file -isnot [IO.FileInfo] -or $file.Length -gt 4MB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Assembly JSON input must be a regular file at most 4 MiB.'}
  $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{
    if($stream.Length -gt 4MB){throw 'Assembly JSON input exceeds 4 MiB.'}
    $bytes=[byte[]]::new([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$read=$stream.Read($bytes,$offset,$bytes.Length-$offset);if(-not $read){throw 'Incomplete assembly JSON read.'};$offset+=$read}
  }finally{$stream.Dispose()}
  [Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)|ConvertFrom-Json -ErrorAction Stop
}
$manifest=Read-AssemblyJson $ManifestPath
$mapping=Read-AssemblyJson $SourceMapPath
if($mapping -isnot [pscustomobject] -or @($mapping.PSObject.Properties).Count -gt 32768){throw 'Source map must be a bounded JSON object.'}
$sources=@{}
foreach($property in $mapping.PSObject.Properties){
  if($sources.ContainsKey($property.Name) -or $property.Value -isnot [string]){throw 'Invalid or duplicate source-map entry.'}
  $sources[$property.Name]=$property.Value
}
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.OfflineBundle.psm1') -Force
New-RideOfflineBundle -Manifest $manifest -SourceFiles $sources -DestinationPath $DestinationPath -MaximumBytes $MaximumBytes -CoverageProfileId $CoverageProfileId -CatalogFileId $CatalogFileId -WhatIf:$WhatIfPreference
