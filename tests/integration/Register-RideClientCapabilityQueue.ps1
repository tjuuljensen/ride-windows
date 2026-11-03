<#
.SYNOPSIS
  Register or remove an expiring fixed capability acceptance task.
.DESCRIPTION
  Run during an attended elevated session in the already registered owning
  account. Adds two protected worker files, one activation record and one task.
  Does not refresh the package controller, retrieve credentials or change the VM.
  Registration pins the current controller and host sources; edits require a
  later idle remove/register cycle after retained recovery is complete.
.PARAMETER ConfigurationPath
  Existing installed disposable controller configuration.json.
.PARAMETER Action
  Register a fresh task or Remove its task/files while preserving results.
.PARAMETER ExpiresAtUtc
  Explicit expiration, more than 60 minutes and at most 12 hours away.
.PARAMETER ExpectedBuild
  Exact Windows 11 guest build to attest during Prepare.
.PARAMETER ExpectedEditionId
  Exact supported client edition for the disposable fixture.
.PARAMETER ExpectedRevision
  Exact guest update build revision; no default revision is inferred.
.PARAMETER Version
  Print the script version without host access.
.EXAMPLE
  .\Register-RideClientCapabilityQueue.ps1 -ConfigurationPath C:\ProgramData\RIDE\TestAutomation\Lab\configuration.json -ExpiresAtUtc '2026-11-04T05:30:00Z' -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -ExpectedRevision 9711 -WhatIf
.INPUTS
  Registered configuration and current source checkout.
.OUTPUTS
  Preview, Registered or Removed record. No native acceptance claim.
.NOTES
  Compatibility: Windows PowerShell 5.1 x64; existing elevation for writes.
  Effects: Only this dedicated task and three named protected files; no UAC.
  Recovery: No replacement over active work. Results and guest holds are preserved.
  Version: 0.1.0. Changelog: Add explicit expiring capability queue activation.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([string]$ConfigurationPath,[ValidateSet('Register','Remove')][string]$Action='Register',
  [datetimeoffset]$ExpiresAtUtc,[ValidatePattern('^[0-9]{5,8}$')][string]$ExpectedBuild,
  [ValidateSet('Professional','ProfessionalN','ProfessionalEducation','ProfessionalEducationN','ProfessionalWorkstation','ProfessionalWorkstationN','Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')][string]$ExpectedEditionId,
  [ValidateRange(0,2147483647)][int]$ExpectedRevision,[switch]$Version)
if($Version){'0.1.0';return}
$ErrorActionPreference='Stop'
if(-not $ConfigurationPath){throw 'ConfigurationPath is required.'}
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess){throw 'Use native Windows PowerShell 5.1 x64.'}
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE.ClientCapabilityQueue.psm1') -Force
$configuration=Read-RideAutomationConfiguration $ConfigurationPath
$root=Get-RideAutomationRoot $configuration.Name
$installedConfiguration=Join-Path $root 'configuration.json'
if([IO.Path]::GetFullPath($ConfigurationPath) -ine $installedConfiguration -or [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\') -ine [IO.Path]::GetFullPath($configuration.LocalRepositoryPath).TrimEnd('\')){throw 'Use the installed configuration and its registered checkout.'}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $configuration.HostAccountSid){throw 'Use the registered owning account.'}
if(-not $WhatIfPreference -and -not (Test-RideAutomationAdministrator)){throw 'Use an existing elevated session; this script does not request UAC.'}
$taskName=$configuration.Name+'Capabilities';$activationPath=Join-Path $root 'bin/capability-queue-activation.json'
$fileNames=@('RIDE.ClientCapabilityQueue.psm1','Invoke-RideClientCapabilityQueueWorker.ps1','capability-queue-activation.json')
foreach($path in @($root,(Join-Path $root 'bin'),$installedConfiguration)){Assert-RideAutomationDirectory $path}
$activation=$null
if($Action -eq 'Register'){
  foreach($name in @('ExpiresAtUtc','ExpectedBuild','ExpectedEditionId','ExpectedRevision')){if(-not $PSBoundParameters.ContainsKey($name)){throw "Register requires explicit $name."}}
  $now=[datetimeoffset]::UtcNow
  if($ExpiresAtUtc -le $now.AddMinutes(60) -or $ExpiresAtUtc -gt $now.AddHours(12)){throw 'Choose an expiration more than 60 minutes and no more than 12 hours away.'}
  $activation=[pscustomobject][ordered]@{SchemaVersion=1;Kind='ClientCapabilityQueueActivation';ActivationId=[guid]::NewGuid().ToString('N');Name=$configuration.Name;TaskName=$taskName;HostAccountSid=$configuration.HostAccountSid;VMId=$configuration.VMId;CheckpointId=$configuration.CheckpointId;LocalRepositoryPath=$configuration.LocalRepositoryPath;ConfigurationSha256=(Get-FileHash -LiteralPath $installedConfiguration).Hash;CreatedAtUtc=$now.ToString('o');ExpiresAtUtc=$ExpiresAtUtc.ToUniversalTime().ToString('o');ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;ExpectedRevision=$ExpectedRevision;HostSources=@(New-RideCapabilityQueueSourceManifest $configuration.LocalRepositoryPath)}
  Assert-RideCapabilityQueueActivation $activation $configuration $activation.ConfigurationSha256
}
if(-not $PSCmdlet.ShouldProcess($taskName,"$Action the finite expiring OpenSSH/RSAT acceptance queue")){
  [pscustomobject]@{Status='Preview';Action=$Action;TaskName=$taskName;VMChanged=$false;SourceCount=if($activation){$activation.HostSources.Count}else{0}};return
}
$queueLock=$null;$workerLock=$null
try{
  $queueLock=[IO.File]::Open((Join-Path $root 'runtime/capability-queue.lock'),'OpenOrCreate','ReadWrite','None')
  $workerLock=[IO.File]::Open((Join-Path $root 'runtime/worker.lock'),'OpenOrCreate','ReadWrite','None')
  foreach($name in @('blocked.json','capability-pending.json','capability-running.json')){if(Test-Path -LiteralPath (Join-Path $root ('runtime/'+$name))){throw 'Complete or inspect retained/queued recovery before changing registration.'}}
  if((Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $configuration.Name).State -ne 'Ready'){throw 'Package controller must be idle.'}
  foreach($queue in @('pending','running')){if(@(Get-ChildItem -LiteralPath (Join-Path $root ('queue/'+$queue)) -File).Count){throw 'Package queue must be empty.'}}
  $existing=Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $taskName -ErrorAction SilentlyContinue
  if($Action -eq 'Remove'){
    if($existing -and $existing.State -ne 'Ready' -and $existing.State -ne 'Disabled'){throw 'Capability task must be idle before removal.'}
    if(Test-Path -LiteralPath $activationPath){
      $old=Get-Content -LiteralPath $activationPath -Raw|ConvertFrom-Json
      if($old.Kind -cne 'ClientCapabilityQueueActivation' -or $old.ActivationId -cnotmatch '^[a-f0-9]{32}$' -or $old.Name -cne $configuration.Name -or $old.TaskName -cne $taskName){throw 'Existing activation identity differs; inspect it before removal.'}
      $archive=Join-Path $root ('results/capability-activation-'+$old.ActivationId+'.json')
      if(-not (Test-Path -LiteralPath $archive)){Copy-Item -LiteralPath $activationPath -Destination $archive}
    }
    if($existing){Unregister-ScheduledTask -TaskPath '\RIDE\' -TaskName $taskName -Confirm:$false}
    foreach($name in $fileNames){$path=Join-Path $root ('bin/'+$name);Assert-RideAutomationDirectory $path;if(Test-Path -LiteralPath $path -PathType Leaf){Remove-Item -LiteralPath $path}}
    [pscustomobject]@{Status='Removed';TaskName=$taskName;VMChanged=$false;ResultsPreserved=$true};return
  }
  if($existing){throw 'Capability task already exists; no replacement.'}
  foreach($name in $fileNames){if(Test-Path -LiteralPath (Join-Path $root ('bin/'+$name))){throw 'Protected capability files already exist; inspect prior registration.'}}
  foreach($name in $fileNames|Where-Object {$_ -ne 'capability-queue-activation.json'}){
    $source=Join-Path $PSScriptRoot $name;$destination=Join-Path $root ('bin/'+$name)
    Copy-Item -LiteralPath $source -Destination $destination
    if((Get-FileHash -LiteralPath $source).Hash -cne (Get-FileHash -LiteralPath $destination).Hash){throw 'Protected worker copy differs.'}
  }
  Write-RideAutomationJson $activationPath $activation
  foreach($name in $fileNames){
    $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($configuration.HostAccountSid),'ReadAndExecute','Allow'))
    Set-Acl -LiteralPath (Join-Path $root ('bin/'+$name)) -AclObject $acl
  }
  $worker=Join-Path $root 'bin/Invoke-RideClientCapabilityQueueWorker.ps1'
  $executable=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
  $taskAction=New-ScheduledTaskAction -Execute $executable -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$worker`" -ActivationPath `"$activationPath`"" -WorkingDirectory (Join-Path $root 'bin')
  $principal=New-ScheduledTaskPrincipal -UserId $configuration.HostAccountSid -LogonType Interactive -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([timespan]::FromMinutes(45)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  $null=Register-ScheduledTask -TaskPath '\RIDE\' -TaskName $taskName -Action $taskAction -Principal $principal -Settings $settings -Description ('Expiring fixed RIDE OpenSSH/RSAT retained acceptance; '+$activation.ExpiresAtUtc)
  $service=New-Object -ComObject Schedule.Service;$service.Connect()
  $service.GetFolder('\RIDE').GetTask($taskName).SetSecurityDescriptor("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;$($configuration.HostAccountSid))",0)
  [pscustomobject]@{Status='Registered';TaskName=$taskName;ActivationId=$activation.ActivationId;ExpiresAtUtc=$activation.ExpiresAtUtc;HostSourceCount=$activation.HostSources.Count;VMChanged=$false;NativeAcceptancePassed=$false}
}finally{if($workerLock){$workerLock.Dispose()};if($queueLock){$queueLock.Dispose()}}
