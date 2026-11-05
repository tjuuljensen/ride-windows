<#
.SYNOPSIS
  Read or write a synthetic progress file in an independent PowerShell process.
.DESCRIPTION
  Used by AutomationWatchdog.Tests.ps1. The writer pauses after Stage 1 until
  the reader observes it, then publishes the remaining stages during polling.
.PARAMETER Role
  Reader or Writer.
.PARAMETER ModulePath
  Path to the controller module under test.
.PARAMETER Directory
  Existing Pester fixture directory containing the initial progress snapshot.
.PARAMETER RunId
  Correlated synthetic request ID.
.EXAMPLE
  Invoke-Pester .\tests\AutomationWatchdog.Tests.ps1
.NOTES
  Version 0.1.0. Windows PowerShell 5.1. Uses only fixture files.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Reader','Writer')][string]$Role,
  [Parameter(Mandatory)][string]$ModulePath,
  [Parameter(Mandatory)][string]$Directory,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId
)
$ErrorActionPreference='Stop'
Import-Module $ModulePath -ErrorAction Stop
$ready=Join-Path $Directory 'stage-one-observed'
$progress=Join-Path $Directory 'host-phase.json'
$deadline=[datetime]::UtcNow.AddSeconds(45)
if($Role -eq 'Writer'){
  Write-RideAutomationHostProgress $Directory $RunId Preparation 'Stage 1'
  while(-not [IO.File]::Exists($ready)){
    if([datetime]::UtcNow -ge $deadline){throw 'Reader did not observe Stage 1.'}
    Start-Sleep -Milliseconds 25
  }
  foreach($i in 2..150){Write-RideAutomationHostProgress $Directory $RunId Preparation "Stage $i"}
  return
}
$reads=0
do {
  $snapshot=Read-RideAutomationHostProgress $progress
  if($snapshot.RunId -cne $RunId -or $snapshot.Phase -cne 'Preparation' -or
     $snapshot.Stage -cnotmatch '^(Initial|Stage [1-9][0-9]{0,2})$'){throw 'Invalid progress snapshot.'}
  $reads++
  if($snapshot.Stage -ceq 'Stage 1' -and -not [IO.File]::Exists($ready)){[IO.File]::WriteAllText($ready,$RunId)}
  if($snapshot.Stage -ceq 'Stage 150'){break}
  if([datetime]::UtcNow -ge $deadline){throw 'Writer did not reach Stage 150.'}
  Start-Sleep -Milliseconds 25
} while($true)
[IO.File]::WriteAllText((Join-Path $Directory 'reader-count.txt'),[string]$reads)
