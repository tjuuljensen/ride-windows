<#
.SYNOPSIS
  Summarize captured process samples without treating them as behavioral proof.

.DESCRIPTION
  Returns phase-level simultaneous memory totals for workload, separately assigned
  console processes and sampler. Reports median, p95 and sampled peaks in bytes.
  I/O counter deltas are observed lower bounds, not physical disk-write volume.
  Reads capture files only. Never launches a workload or edits results. Rejects
  legacy decimal-comma timing fields so they cannot be misread as thousands.
.PARAMETER RunDirectory
  Directory containing metadata.json, processes.json and samples.csv.
.PARAMETER AssignedConsoleKey
  Process identity keys associated with the workload by separate trace review.
  Complete keys from processes.json. Unassigned candidates are excluded from totals.
.PARAMETER Version
  Print tooling version without reading results.
.EXAMPLE
  .\tests\integration\Get-RideScreenLockSummary.ps1 -RunDirectory E:\evidence\ps51-light-1
  Review process identities, then repeat with AssignedConsoleKey where needed.
.INPUTS
  None.
.OUTPUTS
  PSCustomObject. Per-phase/group memory statistics and per-process I/O deltas.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; verified with synthetic data.
  Author: RIDE-Windows maintainers. Version: 0.1.1
  Changelog: 0.1.1: Reject ambiguous legacy locale-specific timing fields.
  0.1.0: Add simultaneous memory totals and explicit I/O limitations.
.LINK
  ../../docs/SCREEN-LOCK-IMPACT.md
#>
[CmdletBinding()]
param(
  [string] $RunDirectory,
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      if (-not $fakeBoundParameters.RunDirectory) { return }
      Get-Content -LiteralPath (Join-Path $fakeBoundParameters.RunDirectory 'processes.json') -Raw -ErrorAction Stop | ConvertFrom-Json |
        Where-Object { $_.Name -match '^(conhost|OpenConsole|WindowsTerminal)\.exe$' } | ForEach-Object Key |
        Sort-Object -Unique | Where-Object { $_.StartsWith($wordToComplete, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object {
          [Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    } catch { }
  })][string[]] $AssignedConsoleKey = @(),
  [switch] $Version
)
$script:ScriptVersion = '0.1.1'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $RunDirectory) { throw 'RunDirectory is required.' }
$metadata = Get-Content -LiteralPath (Join-Path $RunDirectory 'metadata.json') -Raw | ConvertFrom-Json
$samples = @(Import-Csv -LiteralPath (Join-Path $RunDirectory 'samples.csv'))
if (@($samples | Where-Object { $_.Sample -match ',' -or $_.GapSeconds -match ',' }).Count) {
  throw 'Legacy locale-specific timing fields require a reviewed invariant conversion using the recorded capture culture. Preserve the raw CSV; do not interpret decimal commas as thousands.'
}
$identities = @(Get-Content -LiteralPath (Join-Path $RunDirectory 'processes.json') -Raw | ConvertFrom-Json)
foreach ($key in $AssignedConsoleKey) {
  if (-not @($identities | Where-Object { $_.Key -eq $key -and $_.Name -match '^(conhost|OpenConsole|WindowsTerminal)\.exe$' }).Count) { throw "Unknown console identity: $key" }
}
function Get-Statistics {
  param([double[]] $Values)
  $sorted = @($Values | Sort-Object)
  if (-not $sorted.Count) { return $null }
  $middle = [int][Math]::Floor($sorted.Count / 2)
  $median = if ($sorted.Count % 2) { $sorted[$middle] } else { ($sorted[$middle - 1] + $sorted[$middle]) / 2 }
  [pscustomobject]@{ Median = $median; P95 = $sorted[[Math]::Max(0, [int][Math]::Ceiling($sorted.Count * 0.95) - 1)]; SampledPeak = $sorted[-1] }
}
$totals = foreach ($sample in $samples | Group-Object Sample) {
  foreach ($groupName in @('WorkloadWithAssignedConsole', 'Sampler', 'UnassignedConsole')) {
    $members = @($sample.Group | Where-Object {
      if ($groupName -eq 'WorkloadWithAssignedConsole') { $_.Role -eq 'Workload' -or $_.ProcessKey -in $AssignedConsoleKey }
      elseif ($groupName -eq 'Sampler') { $_.Role -eq 'Sampler' }
      else { $_.Role -eq 'ConsoleCandidate' -and $_.ProcessKey -notin $AssignedConsoleKey }
    })
    [pscustomobject]@{
      Phase = $sample.Group[0].Phase; Group = $groupName; Sample = [double]$sample.Name
      WorkingSetBytes = ($members | ForEach-Object { [double]$_.WorkingSetBytes } | Measure-Object -Sum).Sum
      PrivateBytes = if (@($members | Where-Object { [string]::IsNullOrWhiteSpace($_.PrivateBytes) }).Count) { $null } else { ($members | ForEach-Object { [double]$_.PrivateBytes } | Measure-Object -Sum).Sum }
      PrivateReadIncomplete = [bool](@($members | Where-Object { [string]::IsNullOrWhiteSpace($_.PrivateBytes) }).Count)
      GapSeconds = [double]$sample.Group[0].GapSeconds
    }
  }
}
$phaseStatistics = foreach ($group in $totals | Group-Object Phase,Group) {
  [pscustomobject]@{
    Phase = $group.Group[0].Phase; Group = $group.Group[0].Group; Samples = $group.Count
    WorkingSetBytes = Get-Statistics @($group.Group.WorkingSetBytes)
    PrivateBytes = Get-Statistics @($group.Group | Where-Object { -not $_.PrivateReadIncomplete } | ForEach-Object PrivateBytes)
    IncompletePrivateSamples = @($group.Group | Where-Object PrivateReadIncomplete).Count
    GapSeconds = Get-Statistics @($group.Group.GapSeconds)
  }
}
$io = foreach ($group in $samples | Where-Object { $_.Role -eq 'Workload' -or $_.ProcessKey -in $AssignedConsoleKey } | Group-Object ProcessKey) {
  foreach ($phase in $group.Group | Group-Object Phase) {
    $bytes = @($phase.Group | ForEach-Object { [double]$_.CumulativeIoWriteBytes } | Sort-Object)
    [pscustomobject]@{ ProcessKey = $group.Name; Phase = $phase.Name; ObservedIoWriteDeltaBytes = $bytes[-1] - $bytes[0] }
  }
}
[pscustomobject]@{
  CaseId = $metadata.CaseId; RunNumber = $metadata.RunNumber; CaptureStatus = $metadata.Status
  AssignedConsoleKeys = $AssignedConsoleKey; Memory = @($phaseStatistics); IoLowerBounds = @($io)
  BehaviorVerified = $false
  Limits = 'Summed working sets can double-count shared resident pages; private bytes is a process commit proxy. Sampled peaks miss subinterval spikes. Review lifetime process peaks and raw traces separately. I/O includes devices/pipes, excludes missed first/final counters, and is not physical disk traffic. Captured is not behavioral acceptance.'
}
