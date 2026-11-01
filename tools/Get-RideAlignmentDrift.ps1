<#
.SYNOPSIS
  Report local RIDE behavior-contract and shared-scenario pin drift.
.DESCRIPTION
  Compares the canonical contract bytes with the Windows consumer reference,
  checks the shared scenario and capability-register versions, and optionally
  compares an explicitly supplied peer reference. The script is read-only and
  performs no network access or runtime acceptance checks.
.PARAMETER RepositoryRoot
  Repository containing the contract, consumer reference, scenarios and register.
.PARAMETER PeerReferencePath
  Optional JSON reference with contractVersion, sha256 and scenarioRevision.
.PARAMETER FailOnDrift
  Throw after emitting the report when a pin mismatch is found.
.EXAMPLE
  ./tools/Get-RideAlignmentDrift.ps1
.EXAMPLE
  ./tools/Get-RideAlignmentDrift.ps1 -PeerReferencePath ./peer-contract-ref.json -FailOnDrift
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Read-only; does not fetch peer state, modify pins, run handlers or contact VMs.
  Changelog: 2026-11-01: Add ALIGN-07 pinned drift report.
#>
[CmdletBinding()]
param(
  [Parameter()][string] $RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
  [Parameter()][string] $PeerReferencePath,
  [Parameter()][switch] $FailOnDrift
)

$ErrorActionPreference = 'Stop'

function Read-JsonFile {
  param([Parameter(Mandatory)][string] $Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required alignment input is missing: $Path" }
  return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
}

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$reference = Read-JsonFile (Join-Path $root 'docs/models/ride-behavior-contract-ref.json')
$scenarios = Read-JsonFile (Join-Path $root 'docs/models/behavior-scenarios.json')
$differences = Read-JsonFile (Join-Path $root 'docs/models/capability-differences.json')
$contractPath = Join-Path $root ([string]$reference.canonicalPath)
if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) { throw "Canonical contract is missing: $contractPath" }
$actualHash = (Get-FileHash -LiteralPath $contractPath -Algorithm SHA256).Hash
$issues = [System.Collections.Generic.List[string]]::new()

if ($actualHash -cne [string]$reference.sha256) { $issues.Add('Canonical contract digest differs from the Windows consumer pin.') }
if ([string]$scenarios.contractVersion -cne [string]$reference.contractVersion) { $issues.Add('Shared scenario contract version differs from the Windows consumer pin.') }
if ([string]$scenarios.contractSha256 -cne [string]$reference.sha256) { $issues.Add('Shared scenario contract digest differs from the Windows consumer pin.') }
if ([string]$differences.contractVersion -cne [string]$reference.contractVersion) { $issues.Add('Capability register contract version differs from the Windows consumer pin.') }

$peerState = 'unavailable'
if ($PeerReferencePath) {
  $peer = Read-JsonFile (Resolve-Path -LiteralPath $PeerReferencePath).Path
  $peerState = 'matches'
  if ([string]$peer.contractVersion -cne [string]$reference.contractVersion) {
    $issues.Add('Peer consumer contract version differs; review compatibility before updating either pin.')
    $peerState = 'drift'
  }
  if ([string]$peer.sha256 -cne [string]$reference.sha256) {
    $issues.Add('Peer consumer contract digest differs; review compatibility before updating either pin.')
    $peerState = 'drift'
  }
  if ($peer.PSObject.Properties.Name -contains 'scenarioRevision' -and [string]$peer.scenarioRevision -cne [string]$scenarios.scenarioRevision) {
    $issues.Add('Peer scenario revision differs; review paired scenario coverage.')
    $peerState = 'drift'
  }
}

$status = if ($issues.Count -gt 0) { 'DriftDetected' } elseif ($peerState -eq 'unavailable') { 'PeerComparisonUnavailable' } else { 'Current' }
$nextAction = if ($issues.Count -gt 0) {
  'Open linked consumer tasks; record compatibility, evidence and next action before changing pins.'
} elseif ($peerState -eq 'unavailable') {
  'Supply the peer consumer reference for cross-repository comparison; no peer drift is inferred.'
} else {
  'No local or supplied peer pin drift detected; runtime and VM acceptance remain separate.'
}

$report = [pscustomobject]@{
  schemaVersion = 1
  status = $status
  contractVersion = [string]$reference.contractVersion
  pinnedSha256 = [string]$reference.sha256
  actualSha256 = $actualHash
  scenarioRevision = [string]$scenarios.scenarioRevision
  peerComparison = $peerState
  issues = @($issues.ToArray())
  nextAction = $nextAction
  readOnly = $true
}
$report
if ($FailOnDrift -and $issues.Count -gt 0) { throw 'RIDE alignment drift detected; review the emitted report.' }
