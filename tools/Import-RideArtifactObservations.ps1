<#
.SYNOPSIS
  Merge collected VM acquisition observations into the shared metadata library.
.DESCRIPTION
  Validates schema, identities, hashes and HTTPS sources. Imports metadata only,
  preserves existing entries, ignores identical observation IDs and rejects
  conflicting IDs. Uses an exclusive library lock and atomic replacement.
.PARAMETER Path
  One or more collected artifact-observations.json files.
.PARAMETER LibraryPath
  Shared library; defaults to catalog/artifact-observations.json in this checkout.
.PARAMETER Version
  Print the script version without reading or writing evidence.
.EXAMPLE
  .\tools\Import-RideArtifactObservations.ps1 -Path C:\results\guest\artifact-observations.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  System.Management.Automation.PSCustomObject. Imported count and library path.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Prerequisites: Read access to collected metadata; write access to the library.
  Recovery: Existing records are retained; failed imports leave input evidence intact.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Reviewable append-only VM evidence import.
#>


[CmdletBinding(SupportsShouldProcess)]
param([string[]] $Path, [string] $LibraryPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/artifact-observations.json'), [switch] $Version)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $Path) { throw '-Path is required.' }
$incoming = foreach ($inputPath in $Path) {
  $inputFile = Get-Item -LiteralPath $inputPath
  if ($inputFile.Length -gt 16MB) { throw 'Observation input exceeds 16 MiB.' }
  $inputLibrary = Get-Content -LiteralPath $inputFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
  if ($inputLibrary.SchemaVersion -ne 1) { throw 'Observation input requires SchemaVersion 1.' }
  foreach ($record in $inputLibrary.Observations) {
    # Older records lacking IDs may accompany snapshots; they are retained in
    # the existing library but are not fabricated as new acquisitions.
    if (-not $record.ObservationId) { continue }
    if ($record.ObservationId -notmatch '^[0-9a-f]{32}$' -or $record.Sha256 -notmatch '^[0-9a-fA-F]{64}$' -or -not [uri]::IsWellFormedUriString([string]$record.SourceUri, [UriKind]::Absolute) -or ([uri]$record.SourceUri).Scheme -ne 'https') { throw 'Invalid acquisition identity, hash or source URI.' }
    foreach ($member in $record.Contents) {
      if ($member.Sha256 -notmatch '^[0-9a-fA-F]{64}$' -or $member.ParentSha256 -ne $record.Sha256) { throw 'Archive member evidence does not match its parent acquisition.' }
    }
    $record
  }
}
if (-not $PSCmdlet.ShouldProcess($LibraryPath, "Merge $(@($incoming).Count) collected observation(s)")) { return }
$LibraryPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LibraryPath)
$libraryLock = $null
$temporaryPath = $LibraryPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
try {
  New-Item -ItemType Directory -Path (Split-Path -Parent $LibraryPath) -Force | Out-Null
  $libraryLock = [IO.File]::Open($LibraryPath + '.lock', [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  $existing = if (Test-Path -LiteralPath $LibraryPath) { Get-Content -LiteralPath $LibraryPath -Raw -Encoding UTF8 | ConvertFrom-Json } else { [pscustomobject]@{ SchemaVersion = 1; Observations = @() } }
  if ($existing.SchemaVersion -ne 1) { throw 'Existing library requires SchemaVersion 1.' }
  $entries = [Collections.Generic.List[object]]::new()
  $ids = @{}
  foreach ($record in $existing.Observations) { $entries.Add($record); if ($record.ObservationId) { $ids[$record.ObservationId] = $record | ConvertTo-Json -Depth 16 -Compress } }
  $imported = 0
  foreach ($record in $incoming) {
    $serialized = $record | ConvertTo-Json -Depth 16 -Compress
    if ($ids.ContainsKey($record.ObservationId)) {
      if ($ids[$record.ObservationId] -cne $serialized) { throw "Conflicting observation ID $($record.ObservationId)." }
      continue
    }
    $ids[$record.ObservationId] = $serialized
    $entries.Add($record)
    $imported++
  }
  $output = @{ SchemaVersion = 1; Observations = @($entries.ToArray()) } | ConvertTo-Json -Depth 16
  [IO.File]::WriteAllText($temporaryPath, $output.Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
  $destinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LibraryPath)
  $sourcePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($temporaryPath)
  if ([IO.File]::Exists($destinationPath)) { [IO.File]::Replace($sourcePath, $destinationPath, [NullString]::Value) }
  else { [IO.File]::Move($sourcePath, $destinationPath) }
  [pscustomobject]@{ Imported = $imported; LibraryPath = $LibraryPath }
}
finally {
  if ($libraryLock) { $libraryLock.Dispose() }
  if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
}
