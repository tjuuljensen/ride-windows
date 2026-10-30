<#
.SYNOPSIS
  Execute one claimed VM request under the queue worker's watchdog.
.DESCRIPTION
  Internal child process. Reads only the fixed running-request path and installed
  configuration. The parent worker retains the exclusive controller lock.
  Do not invoke this entry point directly for ordinary testing.
.PARAMETER ConfigurationPath
  Installed controller configuration path supplied by the worker.
.PARAMETER RunId
  Identifier of the request already claimed by the worker.
.PARAMETER Version
  Print the version without loading configuration or executing a request.
.EXAMPLE
  .\Invoke-RideVmTestRequest.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  Correlated result and host progress records in the controller result directory.
.NOTES
  Windows PowerShell 5.1 on the elevated Hyper-V host. Version: 0.1.0.
  Changelog: 0.1.0: Isolate all request preparation/execution/recovery for supervision.
  Recovery: The parent blocks new requests after an interrupted possible VM change.
#>
[CmdletBinding()]
param([string]$ConfigurationPath,[ValidatePattern('^[a-f0-9]{32}$')][string]$RunId,[switch]$Version)
if($Version){'0.1.0';return}
$ErrorActionPreference='Stop'
if(-not $ConfigurationPath -or -not $RunId){throw 'ConfigurationPath and RunId are required.'}
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
$config=Read-RideAutomationConfiguration $ConfigurationPath
$root=Get-RideAutomationRoot $config.Name
if([IO.Path]::GetFullPath($ConfigurationPath) -ine (Join-Path $root 'configuration.json')){throw 'Expected the installed controller configuration.'}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $config.HostAccountSid){throw 'Worker identity differs from configured account.'}
$request=Get-Content -LiteralPath (Join-Path $root "queue\running\$RunId.json") -Raw|ConvertFrom-Json
if($request.RunId -cne $RunId){throw 'Claimed request correlation failed.'}
$result=Invoke-RideAutomationRequest -Configuration $config -Request $request -Root $root -Supervised
if($result.Status -ne 'Passed'){exit 1}
