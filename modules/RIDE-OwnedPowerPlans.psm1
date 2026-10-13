<#
.SYNOPSIS
  Create separately owned, inactive copies of exact power-plan GUIDs.
.DESCRIPTION
  Inspection uses powercfg queries and bounded ownership records without writing.
  Creation records intent before duplication and fingerprints a native export.
  Recovery deletes only the same owned, unchanged, inactive destination. It never
  selects a plan, adopts an existing destination or resets built-in plans.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: powercfg; machine administrator; engine-protected machine state.
  Recovery: Compensating; incomplete ownership or changed/active copies require
  manual review. Internal setters require engine capture and ShouldProcess gates.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add pending owned-copy lifecycle; no target acceptance claimed.
.LINK
  ../docs/owned-power-plans.md
.LINK
  https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
#>

$script:ModuleVersion = '0.1.0'
$ErrorActionPreference = 'Stop'
$script:GuidPattern = '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

function Invoke-RideOwnedPlanCommand {
  param([string[]] $Arguments)
  $previous = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = @(& (Join-Path $env:WINDIR 'System32/powercfg.exe') @Arguments 2>&1)
    $code = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $previous }
  [pscustomobject]@{ ExitCode = $code; Output = ($output -join "`n") }
}

function Assert-RideOwnedPlanOperation {
  param([hashtable] $Operation)
  if ($Operation.Kind -ne 'OwnedPowerPlan' -or $Operation.Scope -ne 'Machine' -or
      $Operation.Id -notmatch '^windows\.[a-z0-9-]+$' -or
      $Operation.SourcePowerPlanGuid -notmatch $script:GuidPattern -or
      $Operation.States.Count -ne 1 -or $Operation.States.Create -isnot [bool] -or
      $Operation.States.Create -ne $true) { throw 'Invalid owned power-plan catalog identity or creation state.' }
}

function Assert-RideOwnedPlanPath {
  param([string] $Path)
  if (-not [IO.Path]::IsPathRooted($Path)) { throw 'Ownership paths must be absolute.' }
  $cursor = [IO.Path]::GetFullPath($Path)
  while ($cursor) {
    if (Test-Path -LiteralPath $cursor -ErrorAction Stop) {
      $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Ownership paths cannot traverse reparse points.' }
    }
    $parent = Split-Path -Parent $cursor
    if ($parent -eq $cursor) { break }
    $cursor = $parent
  }
}

function Get-RideOwnedPlanFile {
  param([hashtable] $Operation, [string] $OwnershipRoot)
  Assert-RideOwnedPlanOperation $Operation
  Assert-RideOwnedPlanPath $OwnershipRoot
  $path = Join-Path $OwnershipRoot ($Operation.Id + '.json')
  Assert-RideOwnedPlanPath $path
  $path
}

function Get-RideOwnedPlanRecord {
  param([hashtable] $Operation, [string] $OwnershipRoot)
  $path = Get-RideOwnedPlanFile $Operation $OwnershipRoot
  if ((Test-Path -LiteralPath $path -ErrorAction Stop) -and -not (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop)) { throw 'Ownership record path is not a regular file.' }
  if (-not (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop)) { return $null }
  if ((Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt 16384) { throw 'Ownership record exceeds 16 KiB.' }
  $record = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
  Assert-RideOwnedPlanRecord $Operation $record
  $record
}

function Assert-RideOwnedPlanRecord {
  param([hashtable] $Operation, $Record)
  if ($Record.Version -ne 1 -or $Record.OperationId -cne $Operation.Id -or
      $Record.SourceGuid -ne $Operation.SourcePowerPlanGuid -or
      $Record.DestinationGuid -notmatch $script:GuidPattern -or
      $Record.DestinationGuid -eq $Record.SourceGuid -or
      $Record.OwnerToken -notmatch $script:GuidPattern -or
      $Record.Stage -notin @('Intent', 'Ready') -or
      ($Record.Stage -eq 'Ready' -and $Record.ExportSha256 -notmatch '^[a-f0-9]{64}$')) {
    throw 'Ownership record identity, stage or export fingerprint is invalid.'
  }
}

function Get-RideOwnedPlanGuids {
  $result = Invoke-RideOwnedPlanCommand @('/list')
  if ($result.ExitCode -ne 0) { throw 'Cannot enumerate power-plan identities.' }
  $guids = @([regex]::Matches($result.Output, '(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b') |
    ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)
  if ($guids.Count -eq 0) { throw 'Power-plan enumeration returned no recognizable identities.' }
  $guids
}

function Get-RideOwnedPlanActiveGuid {
  $result = Invoke-RideOwnedPlanCommand @('/getactivescheme')
  $matches = @([regex]::Matches($result.Output, '(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b'))
  if ($result.ExitCode -ne 0 -or $matches.Count -ne 1) { throw 'Cannot identify the active power-plan GUID.' }
  $matches[0].Value.ToLowerInvariant()
}

function Get-RideOwnedPowerPlanState {
  <#
  .SYNOPSIS
    Read source availability, owned destination identity and active state.
  .PARAMETER Operation
    Exact machine catalog identity and source GUID.
  .PARAMETER OwnershipRoot
    Trusted engine machine-state directory; never taken from a saved snapshot.
  .OUTPUTS
    Versioned capture including proposed identity when no ownership exists. Value
    means a finalized owned copy exists; it does not prove unchanged configuration.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation, [Parameter(Mandatory)][string] $OwnershipRoot)
  $record = Get-RideOwnedPlanRecord $Operation $OwnershipRoot
  $guids = @(Get-RideOwnedPlanGuids)
  $source = Invoke-RideOwnedPlanCommand @('/query', $Operation.SourcePowerPlanGuid)
  $destination = if ($record) { $record.DestinationGuid } else { [guid]::NewGuid().ToString() }
  $exists = $destination -in $guids
  [pscustomobject]@{
    SnapshotVersion = 1; OperationId = $Operation.Id; SourceGuid = $Operation.SourcePowerPlanGuid
    DestinationGuid = $destination; OwnerToken = $(if ($record) { $record.OwnerToken } else { [guid]::NewGuid().ToString() })
    OriginalRecord = $record; OriginalOwned = [bool]($null -ne $record)
    SourceAvailable = [bool]($source.ExitCode -eq 0); Available = $true
    DestinationExists = $exists; Active = [bool]($exists -and (Get-RideOwnedPlanActiveGuid) -eq $destination)
    Value = [bool]($record -and $record.Stage -eq 'Ready' -and $exists)
    Stage = $(if ($record) { $record.Stage } else { 'Absent' })
    ConfigurationComparison = 'Not performed during read-only inspection; checked by export before recovery'
  }
}

function Write-RideOwnedPlanRecord {
  param([hashtable] $Operation, [string] $OwnershipRoot, $Record)
  Assert-RideOwnedPlanRecord $Operation $Record
  $path = Get-RideOwnedPlanFile $Operation $OwnershipRoot
  $temp = Join-Path $OwnershipRoot ([guid]::NewGuid().ToString() + '.tmp')
  try {
    [IO.File]::WriteAllText($temp, ($Record | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temp -Destination $path -Force -ErrorAction Stop
  }
  finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -ErrorAction Stop } }
}

function Get-RideOwnedPlanExportHash {
  param([string] $Guid, [string] $OwnershipRoot)
  if ($Guid -notmatch $script:GuidPattern) { throw 'Invalid export GUID.' }
  Assert-RideOwnedPlanPath $OwnershipRoot
  $path = Join-Path $OwnershipRoot ([guid]::NewGuid().ToString() + '.pow')
  try {
    $result = Invoke-RideOwnedPlanCommand @('/export', $path, $Guid)
    if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Power-plan export failed; unchanged configuration cannot be proven.' }
    Assert-RideOwnedPlanPath $path
    $size = (Get-Item -LiteralPath $path -ErrorAction Stop).Length
    if ($size -lt 1 -or $size -gt 1048576) { throw 'Power-plan export must be between 1 byte and 1 MiB.' }
    (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  }
  finally { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -ErrorAction Stop } }
}

function Open-RideOwnedPlanLock {
  param([hashtable] $Operation, [string] $OwnershipRoot)
  $null = Get-RideOwnedPlanFile $Operation $OwnershipRoot
  if (-not (Test-Path -LiteralPath $OwnershipRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $OwnershipRoot -ErrorAction Stop | Out-Null
  }
  $path = Join-Path $OwnershipRoot ($Operation.Id + '.lock')
  Assert-RideOwnedPlanPath $path
  [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
}

function Assert-RideOwnedPlanCapture {
  param([hashtable] $Operation, $Capture)
  Assert-RideOwnedPlanOperation $Operation
  if ($Capture.SnapshotVersion -ne 1 -or $Capture.OperationId -cne $Operation.Id -or
      $Capture.SourceGuid -ne $Operation.SourcePowerPlanGuid -or
      $Capture.DestinationGuid -notmatch $script:GuidPattern -or
      $Capture.DestinationGuid -eq $Capture.SourceGuid -or
      $Capture.OwnerToken -notmatch $script:GuidPattern -or $Capture.OriginalOwned -isnot [bool]) {
    throw 'Invalid captured owned power-plan identity.'
  }
  if ($Capture.OriginalOwned) {
    Assert-RideOwnedPlanRecord $Operation $Capture.OriginalRecord
    if ($Capture.OriginalRecord.DestinationGuid -ne $Capture.DestinationGuid -or
        $Capture.OriginalRecord.OwnerToken -ne $Capture.OwnerToken) { throw 'Captured ownership identities disagree.' }
  }
  elseif ($null -ne $Capture.OriginalRecord) { throw 'Absent ownership capture cannot contain an existing record.' }
}

function Set-RideOwnedPowerPlanState {
  <#
  .SYNOPSIS
    Record intent and create a separately owned copy without activating it.
  .PARAMETER Operation
    Exact source identity from the catalog.
  .PARAMETER State
    Create only.
  .PARAMETER ExpectedState
    Engine-saved pre-change capture. Never generate a destination after capture.
  .PARAMETER OwnershipRoot
    Trusted engine machine-state directory.
  .OUTPUTS
    None. Partial creation retains an Intent record for manual review.
  #>
  [CmdletBinding()]
  param([hashtable] $Operation, [string] $State, $ExpectedState, [string] $OwnershipRoot)
  Assert-RideOwnedPlanCapture $Operation $ExpectedState
  if ($State -ne 'Create' -or $ExpectedState.OriginalOwned) { throw 'Creation requires a captured absent ownership record; existing records cannot be adopted or replaced.' }
  $lock = Open-RideOwnedPlanLock $Operation $OwnershipRoot
  try {
    if (Get-RideOwnedPlanRecord $Operation $OwnershipRoot) { throw 'Ownership changed after capture.' }
    if ($ExpectedState.DestinationGuid -in @(Get-RideOwnedPlanGuids)) { throw 'Destination already exists; refusing to adopt or overwrite it.' }
    $source = Invoke-RideOwnedPlanCommand @('/query', $Operation.SourcePowerPlanGuid)
    if ($source.ExitCode -ne 0) { throw 'Source template is unavailable; no fallback or implicit plan creation is permitted.' }
    $record = [pscustomobject]@{
      Version = 1; OperationId = $Operation.Id; SourceGuid = $Operation.SourcePowerPlanGuid
      DestinationGuid = $ExpectedState.DestinationGuid; OwnerToken = $ExpectedState.OwnerToken
      Stage = 'Intent'; ExportSha256 = $null
    }
    Write-RideOwnedPlanRecord $Operation $OwnershipRoot $record
    $result = Invoke-RideOwnedPlanCommand @('/duplicatescheme', $record.SourceGuid, $record.DestinationGuid)
    if ($result.ExitCode -ne 0 -or $record.DestinationGuid -notin @(Get-RideOwnedPlanGuids)) { throw 'Duplication failed or destination is missing. Ownership intent retained; manual review required.' }
    $result = Invoke-RideOwnedPlanCommand @('/changename', $record.DestinationGuid, ('RIDE ' + $Operation.Id), ('Owned copy ' + $record.OwnerToken))
    if ($result.ExitCode -ne 0) { throw 'Copy naming failed. Ownership intent retained; manual review required.' }
    if ((Get-RideOwnedPlanActiveGuid) -eq $record.DestinationGuid) { throw 'Copy unexpectedly became active. Ownership intent retained; manual review required.' }
    $record.ExportSha256 = Get-RideOwnedPlanExportHash $record.DestinationGuid $OwnershipRoot
    $record.Stage = 'Ready'
    Write-RideOwnedPlanRecord $Operation $OwnershipRoot $record
  }
  finally { $lock.Dispose() }
}

function Restore-RideOwnedPowerPlanState {
  <#
  .SYNOPSIS
    Delete only an unchanged, inactive, finalized copy owned by the captured run.
  .PARAMETER Operation
    Stable catalog operation identity.
  .PARAMETER Snapshot
    Versioned pre-change capture, including destination and owner token.
  .PARAMETER OwnershipRoot
    Trusted engine machine-state directory; snapshot paths are never used.
  .OUTPUTS
    None. Active, changed, orphaned or incomplete copies are retained for review.
  #>
  [CmdletBinding()]
  param([hashtable] $Operation, $Snapshot, [string] $OwnershipRoot)
  Assert-RideOwnedPlanCapture $Operation $Snapshot
  $lock = Open-RideOwnedPlanLock $Operation $OwnershipRoot
  try {
    $record = Get-RideOwnedPlanRecord $Operation $OwnershipRoot
    $exists = $Snapshot.DestinationGuid -in @(Get-RideOwnedPlanGuids)
    if ($Snapshot.OriginalOwned) {
      if (-not $record -or ($record | ConvertTo-Json -Depth 8 -Compress) -cne ($Snapshot.OriginalRecord | ConvertTo-Json -Depth 8 -Compress)) { throw 'Existing ownership changed; creation recovery cannot reconstruct or replace it.' }
      return
    }
    if (-not $record) {
      if ($exists) { throw 'Destination exists without an ownership record; refusing orphan deletion.' }
      return
    }
    if ($record.OwnerToken -ne $Snapshot.OwnerToken -or $record.DestinationGuid -ne $Snapshot.DestinationGuid -or $record.Stage -ne 'Ready') {
      throw 'Ownership mismatch or incomplete creation; manual review required.'
    }
    if ($exists) {
      if ((Get-RideOwnedPlanActiveGuid) -eq $record.DestinationGuid) { throw 'Owned copy is active; restore the saved selection first.' }
      $hash = Get-RideOwnedPlanExportHash $record.DestinationGuid $OwnershipRoot
      if ($hash -cne $record.ExportSha256) { throw 'Owned copy changed or native export is not reproducible; refusing deletion.' }
      if ((Get-RideOwnedPlanActiveGuid) -eq $record.DestinationGuid) { throw 'Owned copy became active during recovery; refusing deletion.' }
      $result = Invoke-RideOwnedPlanCommand @('/delete', $record.DestinationGuid)
      if ($result.ExitCode -ne 0 -or $record.DestinationGuid -in @(Get-RideOwnedPlanGuids)) { throw 'Owned-copy deletion failed; ownership retained for retry.' }
    }
    Remove-Item -LiteralPath (Get-RideOwnedPlanFile $Operation $OwnershipRoot) -ErrorAction Stop
  }
  finally { $lock.Dispose() }
}

Export-ModuleMember -Function Get-RideOwnedPowerPlanState, Set-RideOwnedPowerPlanState, Restore-RideOwnedPowerPlanState
