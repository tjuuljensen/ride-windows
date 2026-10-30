<#
.SYNOPSIS
Run HashCheck acceptance through a temporary interactive guest task.
.DESCRIPTION
Internal disposable-VM entry point. Requires a signed-in administrator desktop;
no Session 0 fallback. Collects task, worker and suite evidence in ResultsPath.
.PARAMETER GuestPath
Staged RIDE checkout.
.PARAMETER ResultsPath
Correlated guest result directory under C:\RIDE\TestResults.
.PARAMETER RunId
Lowercase 32-character request ID.
.PARAMETER ExpectedComputerName
Expected disposable guest name.
.PARAMETER Worker
Internal scheduled-task worker mode requiring a matching coordinator request.
.PARAMETER ExpectedUserSid
Worker-only pinned guest administrator SID.
.PARAMETER ExpectedSessionId
Worker-only nonzero interactive desktop session.
.PARAMETER Version
Print the version without importing modules or changing state.
.EXAMPLE
.\Invoke-RideInteractiveGuestTests.ps1 -Version
.INPUTS
None.
.OUTPUTS
Suite/completion output and correlated files in ResultsPath.
.NOTES
Windows PowerShell 5.1 on disposable Windows 11. Version 0.1.0.
Requires ScheduledTasks, elevated guest admin and Pester 5.7.1. The host
controller collects results and restores its pinned checkpoint after execution.
.LINK
tests/integration/README.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$GuestPath, [string]$ResultsPath,
  [ValidatePattern('^[a-f0-9]{32}$')][string]$RunId, [string]$ExpectedComputerName,
  [switch]$Worker, [string]$ExpectedUserSid, [int]$ExpectedSessionId, [switch]$Version)
if ($Version) { '0.1.0'; return }
$ErrorActionPreference='Stop'
if (-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Run correlated HashCheck interactive guest acceptance')) { return }
Import-Module (Join-Path $PSScriptRoot 'RIDE.InteractiveGuestTests.psm1') -Force
if ($Worker) {
  Invoke-RideInteractiveGuestWorker -GuestPath $GuestPath -ResultsPath $ResultsPath -RunId $RunId -ExpectedComputerName $ExpectedComputerName -ExpectedUserSid $ExpectedUserSid -ExpectedSessionId $ExpectedSessionId
} else {
  Invoke-RideInteractiveGuestTests -GuestPath $GuestPath -ResultsPath $ResultsPath -RunId $RunId -ExpectedComputerName $ExpectedComputerName -Confirm:$false
}
