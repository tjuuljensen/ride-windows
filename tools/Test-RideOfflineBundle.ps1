<#
.SYNOPSIS
  Verify local integrity for one offline manifest profile without installing it.
.DESCRIPTION
  Loads a bounded JSON manifest and checks selected engine/profile/payload/notice
  files and declared dependencies. No network fallback, installer execution,
  bundled script import, Windows servicing, output file, or deletion occurs.
.PARAMETER ManifestPath
  Explicit local JSON manifest; maximum 4 MiB. Unknown schema/fields are rejected.
.PARAMETER ProfileId
  Exact manifest profile identity. Completion reads only bounded manifest metadata.
.PARAMETER Root
  Local bundle subdirectory; defaults to the manifest's containing directory.
  The manifest uses relative paths, so a copied bundle has no original-host binding.
.PARAMETER MaximumBytes
  Total declared selected-file byte bound, default 128 GiB, maximum 1 TiB.
.PARAMETER CatalogFileId
  Optional catalog Engine file ID from the manifest. Compares the exact local
  catalog/profile bytes with selected package declarations without importing code
  from the bundle. Catalog/profile bounds are 2 MiB/64 KiB.
.EXAMPLE
  .\tools\Test-RideOfflineBundle.ps1 -ManifestPath C:\Offline\bundle-v1\manifest.json -ProfileId workstation | ConvertTo-Json -Depth 12
.EXAMPLE
  .\tools\Test-RideOfflineBundle.ps1 -ManifestPath C:\Offline\bundle-v1\manifest.json -ProfileId workstation -CatalogFileId catalog | ConvertTo-Json -Depth 12
.INPUTS
  None.
.OUTPUTS
  PSCustomObject. Selected declared content completeness and remaining offline gates.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Read access to the explicit bundle; no elevation is requested.
  Recovery: Read-only. Retain failed/missing content and prepare a new bundle version.
  The normal install/apply commands do not yet enforce this preflight. A successful
  hash check is not air-gap readiness, complete dependency discovery or target support.
  Version: 0.2.0.
  Changelog: 0.2.0: Add optional byte-bound catalog/profile package coverage.
    0.1.0: Add bounded local selected-profile preflight and ID completion.
.LINK
  ../docs/offline-bundles.md
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ManifestPath,
  [Parameter(Mandatory)]
  [ArgumentCompleter({
    param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{
      $path=$fakeBoundParameters['ManifestPath']
      if(-not $path){return}
      $file=Get-Item -LiteralPath $path -ErrorAction Stop
      if($file -isnot [IO.FileInfo] -or $file.Length -gt 4MB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){return}
      $manifest=Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
      if($manifest.SchemaVersion -ne 1 -or $manifest.Kind -cne 'RideOfflineBundle' -or @($manifest.Profiles).Count -gt 256){return}
      $manifest.Profiles|Where-Object {$_.Id -is [string] -and $_.Id -match '^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,159}$' -and $_.Id.StartsWith($wordToComplete.Trim("'",'"'),[StringComparison]::OrdinalIgnoreCase)}|Sort-Object Id -Unique|ForEach-Object {
        [Management.Automation.CompletionResult]::new(("'"+$_.Id.Replace("'","''")+"'"),$_.Id,'ParameterValue',$_.Id)
      }
    }catch{}
  })]
  [ValidateNotNullOrEmpty()][string]$ProfileId,
  [string]$Root='',
  [ValidateRange(1,1099511627776)][long]$MaximumBytes=137438953472,
  [ArgumentCompleter({param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{
      $path=$fakeBoundParameters['ManifestPath'];if(-not $path){return}
      $file=Get-Item -LiteralPath $path -ErrorAction Stop
      if($file -isnot [IO.FileInfo] -or $file.Length -gt 4MB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){return}
      $manifest=Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
      if($manifest.SchemaVersion -ne 1 -or $manifest.Kind -cne 'RideOfflineBundle' -or @($manifest.Files).Count -gt 32768 -or @($manifest.Engine.FileIds).Count -gt 4096){return}
      $manifest.Files|Where-Object {$_.Role -ceq 'Engine' -and $_.Id -in $manifest.Engine.FileIds -and $_.Id -is [string] -and $_.Id -match '^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,159}$' -and $_.Id.StartsWith($wordToComplete.Trim("'",'"'),[StringComparison]::OrdinalIgnoreCase)}|Sort-Object Id -Unique|ForEach-Object {
        [Management.Automation.CompletionResult]::new(("'"+$_.Id+"'"),$_.Id,'ParameterValue',$_.RelativePath)
      }
    }catch{}
  })][string]$CatalogFileId
)
$ErrorActionPreference='Stop'
$file=Get-Item -LiteralPath $ManifestPath -ErrorAction Stop
if($file -isnot [IO.FileInfo] -or $file.Length -gt 4MB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Manifest must be a regular JSON file no larger than 4 MiB.'}
if(-not $Root){$Root=$file.DirectoryName}
$stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try{
  if($stream.Length -gt 4MB){throw 'Manifest exceeds 4 MiB.'}
  $buffer=[byte[]]::new([int]$stream.Length);$offset=0
  while($offset -lt $buffer.Length){$read=$stream.Read($buffer,$offset,$buffer.Length-$offset);if(-not $read){throw 'Incomplete manifest read.'};$offset+=$read}
}finally{$stream.Dispose()}
$hash=[Security.Cryptography.SHA256]::Create()
try{$manifestSha256=([BitConverter]::ToString($hash.ComputeHash($buffer))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
try{$text=[Text.UTF8Encoding]::new($false,$true).GetString($buffer).TrimStart([char]0xfeff);$manifest=$text|ConvertFrom-Json -ErrorAction Stop}catch{throw 'Manifest is not valid UTF-8 JSON.'}
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.OfflineBundle.psm1') -Force
$result=Test-RideOfflineBundle -Manifest $manifest -Root $Root -ProfileId $ProfileId -MaximumBytes $MaximumBytes -CatalogFileId $CatalogFileId
$result|Add-Member -NotePropertyName ManifestSha256 -NotePropertyValue $manifestSha256
$result
