<#
.SYNOPSIS
  Execute one fixed retained capability phase from an expiring protected task.
.DESCRIPTION
  Requires attended registration, the owning elevated account, an unchanged
  controller and pinned host sources. Only OpenSSHClient/RSAT Prepare, Lifecycle,
  Collect and Reset are dispatched. Existing retained handlers own VM leases,
  credentials, private evidence and recovery. No automatic reset follows failure.
.PARAMETER ActivationPath
  Protected capability-queue-activation.json next to this installed worker.
.EXAMPLE
  Get-Help .\Invoke-RideClientCapabilityQueueWorker.ps1 -Full
.INPUTS
  One bounded capability-pending.json request under the registered runtime root.
.OUTPUTS
  Correlated phase result under the registered results root.
.NOTES
  Compatibility: Elevated native Windows PowerShell 5.1 x64, registered owner.
  Effects: Only the selected disposable-VM phase; no UAC or task refresh.
  Recovery: Interrupted markers and retained VM holds survive failure/timeout.
  Version: 0.1.0. Changelog: Add fixed expiring capability worker.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ActivationPath)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$expectedActivation=Join-Path $PSScriptRoot 'capability-queue-activation.json'
if([IO.Path]::GetFullPath($ActivationPath) -ine $expectedActivation){throw 'Use only the installed capability activation path.'}
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess){throw 'The capability task requires native Windows PowerShell 5.1 x64.'}
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE.ClientCapabilityQueue.psm1') -Force
Assert-RideAutomationDirectory $ActivationPath
$activationFile=Get-Item -LiteralPath $ActivationPath -Force
if($activationFile.PSIsContainer -or $activationFile.Length -gt 262144){throw 'Invalid protected activation file.'}
$activation=Get-Content -LiteralPath $ActivationPath -Raw|ConvertFrom-Json
$configurationPath=Join-Path $root 'configuration.json'
$configuration=Read-RideAutomationConfiguration $configurationPath
if($root -ine (Get-RideAutomationRoot $configuration.Name) -or
   [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $configuration.HostAccountSid -or
   -not (Test-RideAutomationAdministrator)){throw 'Capability worker account, elevation or installed root differs.'}
Assert-RideCapabilityQueueActivation $activation $configuration (Get-FileHash -LiteralPath $configurationPath).Hash
$pending=Join-Path $root 'runtime/capability-pending.json'
$running=Join-Path $root 'runtime/capability-running.json'
$lock=$null;$leases=@();$report=$null;$powerHeld=$false
try{
  $lock=[IO.File]::Open((Join-Path $root 'runtime/capability-queue.lock'),'OpenOrCreate','ReadWrite','None')
  if(Test-Path -LiteralPath $running){throw 'An interrupted capability request remains; inspect it without deleting its marker.'}
  if(-not (Test-Path -LiteralPath $pending)){return}
  Assert-RideAutomationDirectory $pending
  $item=Get-Item -LiteralPath $pending -Force
  if($item.PSIsContainer -or $item.Length -gt 16384){throw 'Invalid capability request file.'}
  Move-Item -LiteralPath $pending -Destination $running -ErrorAction Stop
  $request=Get-Content -LiteralPath $running -Raw|ConvertFrom-Json
  $selection=Resolve-RideCapabilityQueueRequest $request $activation
  $resultPath=Join-Path $root ('results/capability-'+$request.RequestId+'.json')
  if(Test-Path -LiteralPath $resultPath){throw 'Capability request result already exists; replay refused.'}
  $report=[ordered]@{SchemaVersion=1;Kind='ClientCapabilityQueueResult';ActivationId=$activation.ActivationId;RequestId=$request.RequestId;RunId=$request.RunId;Family=$request.Family;Phase=$request.Phase;Preview=$request.Preview;Status='Running';StartedAtUtc=[datetime]::UtcNow.ToString('o');Error=$null;Result=$null;ServicingStopInferred=$false}
  Write-RideAutomationJson $resultPath $report
  $leases=@(Open-RideCapabilityQueueSourceLease -Repository $configuration.LocalRepositoryPath -Manifest $activation.HostSources)
  if(-not $request.Preview){
    if($request.Phase -cin @('Prepare','Lifecycle') -and (Test-Path -LiteralPath (Join-Path $root 'runtime/capability-stop.json'))){throw 'Capability stop marker is present; no new preparation or lifecycle dispatched.'}
    if((Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $configuration.Name).State -ne 'Ready'){throw 'The package controller must be idle.'}
    foreach($queue in @('pending','running')){if(@(Get-ChildItem -LiteralPath (Join-Path $root ('queue/'+$queue)) -File).Count){throw 'The package queue must be empty.'}}
    Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class RideCapabilityQueuePower { [DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint state); }'
    if([RideCapabilityQueuePower]::SetThreadExecutionState(2147483649) -eq 0){throw 'Cannot hold the system awake for this bounded phase.'}
    $powerHeld=$true
  }
  $hostPath=Join-Path $configuration.LocalRepositoryPath 'tests/integration/RIDE.ClientCapabilityVm.psm1'
  $hostModule=Import-Module $hostPath -Force -PassThru -ErrorAction Stop
  if($request.Phase -cne 'Prepare'){
    $sessionPath=Join-Path $root ('retained-capability-'+$request.RunId+'/session.json')
    $session=& $hostModule {param($p) Read-RideCapabilityVmRecord $p} $sessionPath
    if($session.RunId -cne $request.RunId -or $session.Family -cne $request.Family -or $session.ConfigurationSha256 -cne $activation.ConfigurationSha256){throw 'Retained capability family or controller binding differs.'}
  }
  $parameters=$selection.Parameters;$parameters.ConfigurationPath=$configurationPath
  $report.Result=& $hostModule {param($p) Invoke-RideClientCapabilityVmPhase @p} $parameters
  if($null -eq $report.Result -or @($report.Result).Count -ne 1 -or $report.Result.RunId -cne $request.RunId -or $report.Result.Phase -cne $request.Phase){throw 'Capability phase result correlation differs.'}
  $report.Status=[string]$report.Result.Status
  # A host result or timeout does not prove an in-guest servicing operation stopped.
  # Only the native terminal-result/export safeguards authorize explicit Reset.
}catch{
  if($report){$report.Status='Failed';$report.Error=$_.Exception.Message}else{throw}
}finally{
  if($powerHeld){$null=[RideCapabilityQueuePower]::SetThreadExecutionState(2147483648)}
  foreach($lease in $leases){$lease.Dispose()}
  try{
    if($report){
      $report.FinishedAtUtc=[datetime]::UtcNow.ToString('o')
      Write-RideAutomationJson $resultPath $report
      Move-Item -LiteralPath $running -Destination (Join-Path $root ('results/capability-'+$request.RequestId+'-request.json')) -ErrorAction Stop
    }
  }finally{if($lock){$lock.Dispose()}}
}
if($report -and $report.Status -ceq 'Failed'){exit 1}
