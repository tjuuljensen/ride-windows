<#
.SYNOPSIS
  Probe controller host preparation with a five-minute watchdog and no VM changes.
.DESCRIPTION
  Requires the registered controller idle. Holds its worker lock, validates host
  dependencies and pinned lab/VM/checkpoint, and copies the approved Local source
  into a unique evidence directory. Never boots, restores or changes the guest.
  Runs host work in a supervised Windows PowerShell child and retains stage logs.
.PARAMETER ConfigurationPath
  Existing installed controller configuration.json.
.PARAMETER OutputDirectory
  New evidence directory. Defaults to a unique .local/controller-probes directory.
.PARAMETER ProbeChild
  Internal fixed-action child switch; not a queue or arbitrary-script interface.
.PARAMETER RunId
  Internal correlation ID supplied by the parent.
.PARAMETER Version
  Print the version without accessing host configuration.
.EXAMPLE
  .\tests\integration\Test-RideVmHostPreparation.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json'
.INPUTS
  None.
.OUTPUTS
  Probe status, last stage and evidence path. A failure throws after recording.
.NOTES
  Windows PowerShell 5.1, elevated registered host account. Version: 0.1.0.
  Changelog: 0.1.0: Add a bounded host-only smoke probe for supervised preparation.
  Writes evidence/source copies only; does not register or start tasks or change VM state.
#>
[CmdletBinding()]
param([string]$ConfigurationPath,[string]$OutputDirectory,[switch]$ProbeChild,
  [ValidatePattern('^[a-f0-9]{32}$')][string]$RunId,[switch]$Version)
if($Version){'0.1.0';return}
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
$config=Read-RideAutomationConfiguration $ConfigurationPath
$root=Get-RideAutomationRoot $config.Name
if([IO.Path]::GetFullPath($ConfigurationPath) -ine (Join-Path $root 'configuration.json')){throw 'Use the installed controller configuration.'}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $config.HostAccountSid -or -not (Test-RideAutomationAdministrator)){throw 'Use elevated PowerShell under the registered host account.'}
if($ProbeChild){
  if(-not $RunId -or -not $OutputDirectory){throw 'Missing probe correlation.'}
  Write-RideAutomationHostProgress $OutputDirectory $RunId Preparation 'Validate host and import dependencies'
  Assert-RideAutomationHost $config
  Write-RideAutomationHostProgress $OutputDirectory $RunId Preparation 'Import lab and verify VM/checkpoint pins'
  $target=Import-RideAutomationLab $config
  if($target.VM.State -ne 'Off'){throw 'Expected the registered test VM Off.'}
  Write-RideAutomationHostProgress $OutputDirectory $RunId Preparation 'Check registered task is idle'
  $task=Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $config.Name
  if($task.State -notin @('Ready','Disabled')){throw 'Expected the registered task Ready or Disabled.'}
  Write-RideAutomationHostProgress $OutputDirectory $RunId Preparation 'Copy approved checkout snapshot'
  $files=@(Copy-RideAutomationSnapshot -Source $config.LocalRepositoryPath -Destination (Join-Path $OutputDirectory 'snapshot/ride-windows'))
  Write-RideAutomationJson (Join-Path $OutputDirectory 'source-files.json') $files
  Write-RideAutomationHostProgress $OutputDirectory $RunId Preparation 'Host preparation probe completed'
  Write-RideAutomationJson (Join-Path $OutputDirectory 'probe-child.json') @{RunId=$RunId;Status='Passed';Files=$files.Count;VMState='Off';TaskState=[string]$task.State;VmChanged=$false}
  return
}
$RunId=[guid]::NewGuid().ToString('N')
if(-not $OutputDirectory){$OutputDirectory=Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) ".local/controller-probes/$RunId"}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Probe output directory already exists.'}
$lock=Enter-RideAutomationWorker $root
if(-not $lock){throw 'The controller worker is active; leave it alone and wait for its result.'}
$process=$null
try{
  foreach($queue in 'pending','running'){
    if(@(Get-ChildItem -LiteralPath "$root\queue\$queue" -Filter '*.json' -File).Count){throw "The $queue queue is not empty."}
  }
  if(Test-Path -LiteralPath "$root\runtime\blocked.json"){throw 'Resolve the existing recovery block before probing.'}
  $null=New-Item -ItemType Directory -Path $OutputDirectory -Force
  Write-RideAutomationHostProgress $OutputDirectory $RunId Preparation 'Starting host-only probe'
  $record=[ordered]@{RunId=$RunId;Status='Failed';VmChanged=$false;Error=$null;Evidence=$OutputDirectory;StartedAtUtc=[datetime]::UtcNow.ToString('o')}
  try{
    $arguments="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -ConfigurationPath `"$ConfigurationPath`" -OutputDirectory `"$OutputDirectory`" -RunId $RunId -ProbeChild"
    $process=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $OutputDirectory 'host-worker.log') -RedirectStandardError (Join-Path $OutputDirectory 'host-worker-errors.log')
    $null=$process.Handle
    $wait=Wait-RideAutomationSupervisedProcess $process $OutputDirectory $RunId ([datetime]::UtcNow.AddMinutes(5))
    $record.LastStage=$wait.State.Stage
    if($wait.TimedOut){$record.Status='TimedOut';throw "Host-only probe timed out at: $($wait.State.Stage)"}
    $process.Refresh()
    if($process.ExitCode -ne 0){throw 'Host-only probe failed; inspect host-worker-errors.log.'}
    $child=Get-Content -LiteralPath (Join-Path $OutputDirectory 'probe-child.json') -Raw|ConvertFrom-Json
    if($child.RunId -cne $RunId -or $child.Status -ne 'Passed' -or $child.VmChanged -ne $false){throw 'Host probe evidence mismatch.'}
    $record.Status='Passed';$record.Files=$child.Files
  }catch{
    $record.Error=$_.Exception.Message
    if($process -and -not $process.HasExited){
      try{Stop-RideAutomationProcess $process}
      catch{Write-RideAutomationJson "$root\runtime\blocked.json" @{RunId=$RunId;Error='Could not stop the host-only probe; inspect processes before further work.'};$record.TerminationError=$_.Exception.Message}
    }
  }
  $record.FinishedAtUtc=[datetime]::UtcNow.ToString('o')
  Write-RideAutomationJson (Join-Path $OutputDirectory 'probe-result.json') $record
  [pscustomobject]$record
  if($record.Status -ne 'Passed'){throw "Host probe $($record.Status). Evidence: $OutputDirectory"}
}finally{if($lock){$lock.Dispose()}}
