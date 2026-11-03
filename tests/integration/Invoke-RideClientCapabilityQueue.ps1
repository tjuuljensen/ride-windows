<#
.SYNOPSIS
  Submit one fixed capability acceptance phase to an attended registration.
.DESCRIPTION
  Uses the existing owning account without UAC. The protected activation binds
  the disposable target, source hashes and expiration. Requests cannot supply
  code, target changes or alternate payload sources. Timeout preserves markers
  and VM holds; it never establishes that guest servicing stopped.
.PARAMETER ConfigurationPath
  Existing installed controller configuration.json.
.PARAMETER Family
  OpenSSHClient or RSAT; must match the retained session after Prepare.
.PARAMETER Phase
  Prepare, Lifecycle, Collect or explicitly requested Reset.
.PARAMETER RunId
  Retained run identity. Generated only for Prepare; reuse it for later phases.
.PARAMETER ServicingSource
  Explicit WindowsUpdate acquisition, required only for Prepare.
.PARAMETER Preview
  Queue the native no-change preview. WhatIf instead previews submission locally.
.PARAMETER Version
  Print the script version without host access.
.EXAMPLE
  .\Invoke-RideClientCapabilityQueue.ps1 -ConfigurationPath C:\ProgramData\RIDE\TestAutomation\Lab\configuration.json -Family OpenSSHClient -Phase Prepare -ServicingSource WindowsUpdate -WhatIf
.INPUTS
  Protected activation and one explicit fixed phase selection.
.OUTPUTS
  Correlated terminal queue result or local submission preview.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Attended elevated registration; owning account remains logged in.
  Effects: One bounded task phase; no UAC, credential prompts or automatic reset.
  Recovery: Inspect retained evidence after timeout; do not delete active markers.
  Version: 0.1.0. Changelog: Add ordinary-account finite capability queue client.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$ConfigurationPath,
  [ValidateSet('OpenSSHClient','RSAT')][string]$Family,
  [ValidateSet('Prepare','Lifecycle','Collect','Reset')][string]$Phase,
  [ValidatePattern('(?-i)^[a-f0-9]{32}$')]
  [ArgumentCompleter({
    param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{
      $configPath=$fakeBoundParameters['ConfigurationPath']
      if(-not $configPath -or -not (Test-Path -LiteralPath $configPath -PathType Leaf)){return}
      $root=Split-Path -Parent $configPath
      Get-ChildItem -LiteralPath $root -Directory -Filter 'retained-capability-*' -ErrorAction Stop |
        Select-Object -First 128 | ForEach-Object {
          $id=$_.Name.Substring('retained-capability-'.Length)
          if($id -cmatch '^[a-f0-9]{32}$' -and $id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){
            [Management.Automation.CompletionResult]::new($id,$id,'ParameterValue',$id)
          }
        }
    }catch{}
  })][string]$RunId,
  [ValidateSet('WindowsUpdate')][string]$ServicingSource,[switch]$Preview,[switch]$Version)
if($Version){'0.1.0';return}
$ErrorActionPreference='Stop'
foreach($required in @('ConfigurationPath','Family','Phase')){if(-not $PSBoundParameters.ContainsKey($required)){throw "Explicit $required is required."}}
foreach($name in @('Family','Phase','ServicingSource')){
  if($PSBoundParameters.ContainsKey($name)){
    $valid=@($MyInvocation.MyCommand.Parameters[$name].Attributes|Where-Object {$_ -is [Management.Automation.ValidateSetAttribute]})[0].ValidValues
    $canonical=@($valid|Where-Object {$_ -ieq $PSBoundParameters[$name]})[0]
    switch($name){Family {$Family=$canonical};Phase {$Phase=$canonical};ServicingSource {$ServicingSource=$canonical}}
  }
}
if(-not $RunId){if($Phase -cne 'Prepare'){throw 'Reuse the explicit retained RunId after Prepare.'};$RunId=[guid]::NewGuid().ToString('N')}
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE.ClientCapabilityQueue.psm1') -Force
$configuration=Read-RideAutomationConfiguration $ConfigurationPath
$root=Get-RideAutomationRoot $configuration.Name
if([IO.Path]::GetFullPath($ConfigurationPath) -ine (Join-Path $root 'configuration.json') -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $configuration.HostAccountSid){throw 'Use the installed configuration in the registered owning account.'}
$activationPath=Join-Path $root 'bin/capability-queue-activation.json'
Assert-RideAutomationDirectory $activationPath
$activationFile=Get-Item -LiteralPath $activationPath -Force
if($activationFile.PSIsContainer -or $activationFile.Length -gt 262144){throw 'Invalid protected activation file.'}
$activation=Get-Content -LiteralPath $activationPath -Raw|ConvertFrom-Json
Assert-RideCapabilityQueueActivation $activation $configuration (Get-FileHash -LiteralPath $ConfigurationPath).Hash
$request=[ordered]@{SchemaVersion=1;ActivationId=$activation.ActivationId;RequestId=[guid]::NewGuid().ToString('N');RunId=$RunId;Family=$Family;Phase=$Phase;Preview=[bool]$Preview;SubmittedAtUtc=[datetimeoffset]::UtcNow.ToString('o')}
if($PSBoundParameters.ContainsKey('ServicingSource')){$request.ServicingSource=$ServicingSource}
$null=Resolve-RideCapabilityQueueRequest ([pscustomobject]$request) $activation
if(-not $PSCmdlet.ShouldProcess($activation.TaskName,"Submit $Family $Phase for retained run $RunId")){
  [pscustomobject]@{Status='Preview';SubmissionWritten=$false;TaskStarted=$false;RunId=$RunId;Family=$Family;Phase=$Phase};return
}
$pending=Join-Path $root 'runtime/capability-pending.json';$running=Join-Path $root 'runtime/capability-running.json'
$lock=$null;$stream=$null
try{
  $lock=[IO.File]::Open((Join-Path $root 'runtime/capability-queue.lock'),'OpenOrCreate','ReadWrite','None')
  if((Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $activation.TaskName).State -ne 'Ready'){throw 'Capability task is not ready.'}
  if((Test-Path -LiteralPath $pending) -or (Test-Path -LiteralPath $running)){throw 'A prior capability request remains; inspect it before another submission.'}
  Assert-RideAutomationDirectory $pending
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($request|ConvertTo-Json -Depth 4))
  $stream=[IO.File]::Open($pending,'CreateNew','Write','None');$stream.Write($bytes,0,$bytes.Length);$stream.Flush()
}finally{if($stream){$stream.Dispose()};if($lock){$lock.Dispose()}}
Start-ScheduledTask -TaskPath '\RIDE\' -TaskName $activation.TaskName
$resultPath=Join-Path $root ('results/capability-'+$request.RequestId+'.json')
$deadline=[datetimeoffset]::UtcNow.AddMinutes(46)
do{
  if(Test-Path -LiteralPath $resultPath -PathType Leaf){
    Assert-RideAutomationDirectory $resultPath
    if((Get-Item -LiteralPath $resultPath).Length -gt 4194304){throw 'Capability queue result exceeds its bound.'}
    $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
    foreach($field in @('ActivationId','RequestId','RunId','Family','Phase','Preview')){if($result.$field -cne $request.$field){throw 'Capability result correlation differs.'}}
    if($result.Kind -cne 'ClientCapabilityQueueResult'){throw 'Capability result kind differs.'}
    if($result.Status -cne 'Running' -and -not (Test-Path -LiteralPath $running) -and (Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $activation.TaskName).State -eq 'Ready'){
      if($result.Status -ceq 'Failed'){throw "Capability phase failed. Inspect $resultPath and retained evidence. $($result.Error)"}
      $result;return
    }
  }
  Start-Sleep -Seconds 2
}while([datetimeoffset]::UtcNow -lt $deadline)
throw "Capability wait expired. Inspect $resultPath and retained markers; guest servicing may still be running. No reset or marker deletion was requested."
