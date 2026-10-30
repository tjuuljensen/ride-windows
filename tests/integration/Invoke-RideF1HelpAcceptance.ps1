<#
.SYNOPSIS
  Run the experimental current-user F1 Help lifecycle acceptance on a Lenovo T480.
.DESCRIPTION
  Temporarily enables the pending Windows 11 candidate in the in-memory RIDE
  catalog, then exercises Blocked, WindowsDefault, and exact saved-run restore.
  The built-in catalog remains pending acceptance and is not changed. The user
  must observe Explorer/Desktop and unrelated-application F1 behavior manually.
.EXAMPLE
  .\tests\integration\Invoke-RideF1HelpAcceptance.ps1
.INPUTS
  None.
.OUTPUTS
  String. Progress and path to a sanitized Markdown result report.
.NOTES
  Compatibility: Windows PowerShell 5.1 on Windows 11.
  Prerequisites: Lenovo T480; current user's normal unelevated desktop session;
  reviewed RIDE source copy. No Pester, Git, or third-party software required.
  This test writes only the declared current-user TypeLib values and RIDE state
  records; every captured run is restored in reverse order, including on error.
  Do not run alongside another RIDE setting operation for the same user.
  Version: 0.1.0.
  Changelog: 0.1.0: Initial test-only F1 candidate lifecycle runner.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$OutputDirectory = $env:TEMP
)

$ErrorActionPreference = 'Stop'
$operationId = 'windows.explorer-f1-help'
$runIds = New-Object 'System.Collections.Generic.List[string]'
$restoredRunIds = @{}
$observations = New-Object 'System.Collections.Generic.List[string]'
$restoreErrors = New-Object 'System.Collections.Generic.List[string]'
$initialStateJson = $null
$reportPath = $null

function ConvertTo-SanitizedStateSummary {
  param([Parameter(Mandatory)]$State)
  @($State.Values | ForEach-Object {
    '{0}: exists={1}, type={2}' -f $_.Key, $_.Exists, $(if ($_.ValueType) { $_.ValueType } else { 'none' })
  }) -join '; '
}

function Get-RideRunIdFromOutput {
  param([object[]]$Output)
  $line = @($Output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: ' } | Select-Object -Last 1)
  if ($line.Count -ne 1) { throw 'RIDE did not return a saved Run ID; stop and inspect the RIDE state before continuing.' }
  ($line[0] -replace '^Run ID: ', '').Trim()
}

function Invoke-F1State {
  param([Parameter(Mandatory)][string]$State)
  $plan = @(Get-RideSingleOperationPlan -Id $operationId -Action Set -State $State)
  $before = Get-RideCurrentState -Operation (Get-RideOperation -Id $operationId)
  Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
  $afterPreview = Get-RideCurrentState -Operation (Get-RideOperation -Id $operationId)
  if ((ConvertTo-Json -InputObject $before -Depth 30 -Compress) -cne (ConvertTo-Json -InputObject $afterPreview -Depth 30 -Compress)) {
    throw "Preview for '$State' changed registry state."
  }
  $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
  $runId = Get-RideRunIdFromOutput -Output $output
  $runIds.Add($runId)
  $runId
}

function Restore-F1Run {
  param([Parameter(Mandatory)][string]$RunId)
  Restore-RideRun -RunId $RunId -Confirm:$false | Out-Null
  $restoredRunIds[$RunId] = $true
}

function Add-UserObservation {
  param([Parameter(Mandatory)][string]$Prompt)
  $value = Read-Host $Prompt
  if ([string]::IsNullOrWhiteSpace($value)) { $value = 'No observation entered.' }
  $observations.Add(($value -replace '[\r\n|]+', ' '))
}

try {
  if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1) {
    throw 'Run this acceptance procedure in Windows PowerShell 5.1.'
  }
  Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE-RegistryValueSet.psm1') -Force
  if ((Get-RidePlatform) -ne 'Windows 11') { throw 'The experimental candidate is limited to a Windows 11 test target.' }
  $computer = Get-CimInstance -ClassName Win32_ComputerSystem
  $manufacturer = [string]$computer.Manufacturer
  if ($manufacturer -notmatch 'Lenovo') {
    throw 'This physical acceptance procedure is restricted to the Lenovo test laptop.'
  }
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run unelevated in the intended desktop user session; this is a per-user setting.'
  }
  $confirmation = Read-Host 'Type T480 to confirm this is the prepared Lenovo T480'
  if ($confirmation -cne 'T480') { throw 'T480 confirmation did not match; no change made.' }

  $catalog = Get-RideCatalog
  $operation = @($catalog.Operations | Where-Object Id -EQ $operationId)
  if ($operation.Count -ne 1 -or -not $operation[0].PendingAcceptance -or 'Windows 11' -notin @($operation[0].CandidateTargets)) {
    throw 'The reviewed pending Windows 11 candidate is missing or has an unexpected target declaration.'
  }

  # Enable this candidate for this process only. Do not change published support.
  $operation[0].SupportedTargets = @('Windows 11')
  $operation[0].PendingAcceptance = $false
  $engineModule = Get-Module RIDE.Engine
  & $engineModule {
    param($CandidateCatalog)
    $script:RideLibraryContext = @{ Catalog = $CandidateCatalog; Libraries = @(); ProfileFiles = @() }
  } $catalog

  $target = "$operationId on this unelevated T480 user session"
  if (-not $PSCmdlet.ShouldProcess($target, 'Temporarily apply F1 Help candidate, test both states, and restore captured registry state')) {
    return
  }

  $effectiveOperation = Get-RideOperation -Id $operationId
  $initialState = Get-RideCurrentState -Operation $effectiveOperation
  $initialStateJson = ConvertTo-Json -InputObject $initialState -Depth 30 -Compress
  Write-Output ('Starting registry summary: {0}' -f (ConvertTo-SanitizedStateSummary -State $initialState))
  Write-Output 'Record baseline F1 behavior in File Explorer, on the desktop, and in one unrelated application before continuing.'
  [void](Read-Host 'Press Enter after recording the baseline observations')

  $blockedRunId = Invoke-F1State -State 'Blocked'
  Write-Output ("RIDE applied Blocked; saved Run ID: {0}" -f $blockedRunId)
  $blockedPlan = @(Get-RideSingleOperationPlan -Id $operationId -Action Set -State 'Blocked')
  $blockedRepeat = @(Invoke-RidePlan -Plan $blockedPlan -Confirm:$false)
  if ('No changes were needed; no state record was created.' -notin $blockedRepeat -or -not (Test-RideDesiredState -Operation $effectiveOperation -State 'Blocked')) {
    throw 'Repeated Blocked apply was not an idempotent no-op.'
  }
  Write-Output 'Repeated Blocked apply passed the idempotence check.'
  Write-Output 'Test F1 in File Explorer and on the desktop. Confirm F1 behavior in your selected unrelated application is unchanged.'
  Add-UserObservation -Prompt 'Summarize F1 behavior with Blocked state (do not enter private data)'

  $defaultRunId = Invoke-F1State -State 'WindowsDefault'
  Write-Output ("RIDE applied WindowsDefault; saved Run ID: {0}" -f $defaultRunId)
  $defaultPlan = @(Get-RideSingleOperationPlan -Id $operationId -Action Set -State 'WindowsDefault')
  $defaultRepeat = @(Invoke-RidePlan -Plan $defaultPlan -Confirm:$false)
  if ('No changes were needed; no state record was created.' -notin $defaultRepeat -or -not (Test-RideDesiredState -Operation $effectiveOperation -State 'WindowsDefault')) {
    throw 'Repeated WindowsDefault apply was not an idempotent no-op.'
  }
  Write-Output 'Repeated WindowsDefault apply passed the idempotence check.'
  Write-Output 'Test F1 in File Explorer, on the desktop, and in your unrelated application again. WindowsDefault removes these overrides; it does not guarantee that Help opens.'
  Add-UserObservation -Prompt 'Summarize F1 behavior with WindowsDefault state, including unrelated-app behavior (no private data)'

  Restore-F1Run -RunId $defaultRunId
  if (-not (Test-RideDesiredState -Operation $effectiveOperation -State 'Blocked')) {
    throw 'Restoring the WindowsDefault run did not return the candidate to Blocked state.'
  }
  Write-Output 'Exact restore of the WindowsDefault run returned the setting to Blocked.'

  Restore-F1Run -RunId $blockedRunId
  $finalState = Get-RideCurrentState -Operation $effectiveOperation
  $exactRestore = (ConvertTo-Json -InputObject $finalState -Depth 30 -Compress) -ceq $initialStateJson
  if (-not $exactRestore) { throw 'Final registry state does not exactly match the captured pre-test state.' }
  Write-Output ('Final exact restore passed. Registry summary: {0}' -f (ConvertTo-SanitizedStateSummary -State $finalState))
}
finally {
  for ($index = $runIds.Count - 1; $index -ge 0; $index--) {
    $runId = $runIds[$index]
    if ($restoredRunIds.ContainsKey($runId)) { continue }
    try { Restore-F1Run -RunId $runId }
    catch { $restoreErrors.Add(('Run {0}: {1}' -f $runId, $_.Exception.GetType().Name)) }
  }

  if ($runIds.Count -gt 0) {
    $resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
    if (-not (Test-Path -LiteralPath $resolvedOutputDirectory -PathType Container)) {
      New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
    }
    $reportPath = Join-Path $resolvedOutputDirectory ('t480-f1-acceptance-{0}.md' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $report = @(
      '# T480 F1 Help acceptance report',
      '',
      ('- Collected: {0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss K')),
      ('- RIDE operation: `{0}`' -f $operationId),
      '- Test scope: experimental current-user TypeLib candidate; no Windows support claim.',
      ('- Saved RIDE run IDs: {0}' -f ($runIds -join ', ')),
      ('- Exact original state restored: {0}' -f [bool]($initialStateJson -and $exactRestore)),
      ('- Restore errors: {0}' -f $(if ($restoreErrors.Count) { $restoreErrors -join '; ' } else { 'None reported' })),
      '',
      '## Visible observations',
      ''
    )
    for ($index = 0; $index -lt $observations.Count; $index++) {
      $stateName = if ($index -eq 0) { 'Blocked' } else { 'WindowsDefault' }
      $report += ('- {0}: {1}' -f $stateName, $observations[$index])
    }
    $report += @('', '## Sanitized registry summary', '')
    if ($null -ne $initialState) { $report += ('- Before: {0}' -f (ConvertTo-SanitizedStateSummary -State $initialState)) }
    if ($null -ne $finalState) { $report += ('- After: {0}' -f (ConvertTo-SanitizedStateSummary -State $finalState)) }
    $report += @('', 'This report intentionally omits raw registry data, account names, and recovery secrets.', '')
    Set-Content -LiteralPath $reportPath -Value $report -Encoding UTF8
    Write-Output ('Acceptance report: {0}' -f $reportPath)
  }
}
