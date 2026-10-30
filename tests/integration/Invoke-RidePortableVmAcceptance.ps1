<#
.SYNOPSIS
  Run reviewed portable package lifecycle checks on the registered disposable VM.
.DESCRIPTION
  Locks the idle controller, verifies pinned VM/checkpoint identities, stages a
  hash-checked checkout and only the selected reviewed archives, and collects evidence
  before restoring the same checkpoint. No utility is launched or approved for
  distribution. Does not change controller registration or Defender settings.
.PARAMETER ConfigurationPath
  Existing installed disposable controller configuration.json.
.PARAMETER ArtifactManifestPath
  JSON array of Id and Path entries for the exact selected retained archives.
.PARAMETER OutputDirectory
  Existing caller-owned directory for a fresh correlated run directory.
.PARAMETER Batch
  MiTeCViewers, MiTeCAnalysisTools, MiTeCSystemAndTelephony, NTCore, NTCoreAdditional, MiTeCMailHistoryViewers, AllReviewed, PSScriptTools, OfflineCaffeine, SQLiteQuery,
  MiTeCUtilityFiles, SysinternalsSuite, SysinternalsProducts, ImageMagick, RawCopy or WinPmem. ImageMagick selects the exact
  pinned portable Q16 7z and runs only a synthetic 1x1 PNG encode/identify check.
  SysinternalsSuite is limited to the exact 164-file archive lifecycle.
  SysinternalsProducts checks only the nine fixed independent product archives;
  it does not launch tools, accept EULAs or include Defender-blocked collections.
  RawCopy selects one pinned x64 package and runs only the generated synthetic NTFS file check.
  WinPmem stages and removes its exact pinned executable without launching it or loading its driver.
  NTCore stages three pinned packages and tests 4GB Patch only against a synthetic PE.
  NTCoreAdditional stages Driver List x64/x86 and Rebel.NET files without launching tools.
  MiTeCMailHistoryViewers checks four pinned package file lifecycles without opening user stores.
  MiTeCSystemAndTelephony checks pinned file staging only; report generation and live TAPI behavior remain outside this route.
  AllReviewed includes both viewer architectures and the fixed NTCore candidates.
  Additional batches are explicit.
.PARAMETER TimeoutMinutes
  Maximum guest check execution time, excluding staging and recovery.
.PARAMETER ControllerRunId
  Internal registered-worker request identity. Requires protected installation,
  a matching running request and the worker-held lock; paths derive from registration.
.PARAMETER Version
  Print the version without accessing Windows or a VM.
.EXAMPLE
  .\Invoke-RidePortableVmAcceptance.ps1 -Version
.INPUTS
  Explicit configuration and local artifact manifest paths.
.OUTPUTS
  result.json, source and payload manifests, guest scenarios and saved state.
.NOTES
  Compatibility: Elevated Windows PowerShell 5.1, registered AutomatedLab host.
  Prerequisites: Idle disposable controller and its existing guest credential.
  Effects: Only the pinned VM is reset, started, tested and reset to Off again.
  Recovery: Finally restores the pinned checkpoint even after guest failure.
  Author: RIDE-Windows maintainers. Version: 0.11.0.
  Changelog: 0.11.0: Add an exact WinPmem file-staging-only batch.
    0.10.0: Add the pinned System Information eXtra and TAPI Monitor batch.
    0.9.0: Add the pinned MiTeC EXE Explorer and HexEdit lifecycle batch.
    0.8.0: Add the pinned RawCopy synthetic-only acceptance batch.
    0.7.0: Add the MiTeC mail/history viewer file-lifecycle batch.
    0.6.0: Add the file-lifecycle-only NTCoreAdditional batch.
    0.5.0: Add the pinned ImageMagick portable Q16 acceptance batch.
    0.4.0: Add the isolated Sysinternals Suite snapshot lifecycle batch.
    0.3.3: Add isolated MiTeC utility file-lifecycle acceptance.
    0.3.2: Add the file-lifecycle-only SQLiteQuery batch.
    0.3.1: Collect synthetic-file 4GB Patch functional evidence.
    0.3.0: Support fixed preregistered batches under the existing worker lock.
    0.2.0: Add explicit source and disconnected offline guest batches.
    0.1.1: Supply the loaded lab to the existing guest credential accessor.
    0.1.0: Add focused MiTeC/NTCore checkpoint-backed acceptance.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$ConfigurationPath,[string]$ArtifactManifestPath,[string]$OutputDirectory,
  [ValidateSet('MiTeCViewers','MiTeCAnalysisTools','MiTeCSystemAndTelephony','NTCore','NTCoreAdditional','MiTeCMailHistoryViewers','AllReviewed','PSScriptTools','OfflineCaffeine','SQLiteQuery','MiTeCUtilityFiles','SysinternalsSuite','SysinternalsProducts','ImageMagick','RawCopy','WinPmem')][string]$Batch='AllReviewed',
  [ValidateRange(1,60)][int]$TimeoutMinutes=20,[string]$ControllerRunId,[switch]$Version)
if($Version){'0.11.0';return}
$ErrorActionPreference='Stop'
if(-not $ConfigurationPath -or (-not $ControllerRunId -and (-not $ArtifactManifestPath -or -not $OutputDirectory))){throw 'ConfigurationPath, ArtifactManifestPath and OutputDirectory are required for standalone execution.'}
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE.PortableAcceptance.psm1') -Force
$config=Read-RideAutomationConfiguration $ConfigurationPath
$root=Split-Path -Parent ([IO.Path]::GetFullPath($ConfigurationPath))
$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if($ControllerRunId){
  if($ControllerRunId -cnotmatch '^[a-f0-9]{32}$' -or $Batch -notin @('NTCore','NTCoreAdditional','MiTeCMailHistoryViewers','MiTeCAnalysisTools','MiTeCSystemAndTelephony','PSScriptTools','OfflineCaffeine','SQLiteQuery','MiTeCUtilityFiles','SysinternalsSuite','SysinternalsProducts','ImageMagick','RawCopy','WinPmem') -or $ArtifactManifestPath -or $OutputDirectory){throw 'Invalid fixed controller invocation.'}
  $protectedRoot=Get-RideAutomationRoot $config.Name
  if($root -ine $protectedRoot -or [IO.Path]::GetFullPath($PSScriptRoot) -ine (Join-Path $protectedRoot 'bin') -or 'FocusedPortableV1' -notin @($config.Capabilities)){throw 'Focused acceptance requires the refreshed protected controller.'}
  $request=Get-Content -LiteralPath (Join-Path $root ('queue/running/'+$ControllerRunId+'.json')) -Raw|ConvertFrom-Json
  Assert-RideAutomationRequest $request
  if($request.RunId -cne $ControllerRunId -or $request.IntegrationSuite -cne $Batch -or $request.Source -ne 'Local' -or $request.UnitOnly){throw 'Controller request does not match the focused batch.'}
  $repo=Join-Path $root ('results/'+$ControllerRunId+'/snapshot/ride-windows')
  $ArtifactManifestPath=Join-Path $config.LocalRepositoryPath ('.local/acceptance-input/'+$Batch+'.json')
  $OutputDirectory=Join-Path $root ('results/'+$ControllerRunId+'/focused')
  $null=New-Item -ItemType Directory -Path $OutputDirectory
}
if(-not $config.IsDisposable -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $config.HostAccountSid -or
   (-not $ControllerRunId -and [IO.Path]::GetFullPath($config.LocalRepositoryPath).TrimEnd('\') -ine $repo.TrimEnd('\'))){throw 'Use the registered disposable controller in its owning account and checkout.'}
$catalogModule=if($ControllerRunId){Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1'}else{Join-Path $repo 'modules/RIDE.CatalogData.psm1'}
Import-Module $catalogModule -Force
$catalog=Import-RideCatalogData (Join-Path $repo 'catalog/operations.psd1')
$cases=@(Get-RidePortableAcceptanceCases -Catalog $catalog -Batch $Batch -ReviewRoot $repo)
$payloads=@(Get-RidePortableAcceptancePayloads -Cases $cases -ManifestPath $ArtifactManifestPath)
$null=Assert-RideAutomationDirectory $OutputDirectory
if(-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)){throw 'OutputDirectory must already exist.'}
if(-not $PSCmdlet.ShouldProcess($config.VMName,"Run $Batch acceptance and restore the existing pinned checkpoint")){return}
$runId=if($ControllerRunId){$ControllerRunId}else{[guid]::NewGuid().ToString('N')}
$output=if($ControllerRunId){[IO.Path]::GetFullPath($OutputDirectory)}else{Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) $runId}
if(-not $ControllerRunId){$null=New-Item -ItemType Directory -Path $output}
$root=Split-Path -Parent ([IO.Path]::GetFullPath($ConfigurationPath))
$guestBase='C:\RIDE\PortableAcceptance\'+$runId
$guestEvidence=Join-Path $guestBase 'evidence'
$result=[ordered]@{RunId=$runId;Batch=$Batch;VM=$config.VMName;VMId=$config.VMId;CheckpointId=$config.CheckpointId;ExpectedCases=$cases.Count;Status='Failed';Error=$null;Cleanup='NotStarted';EvidenceCollected=$false;ToolExecuted=$false;FunctionalAcceptance='Pending'}
$lock=$null;$session=$null;$job=$null;$touched=$false
try{
  Assert-RideAutomationHost $config
  if($ControllerRunId){
    $workerLockHeld=$false
    try{$probe=[IO.File]::Open((Join-Path $root 'runtime/worker.lock'),'Open','Read','None');$probe.Dispose()}catch [IO.IOException]{$workerLockHeld=$true}
    if(-not $workerLockHeld -or (Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $config.Name).State -ne 'Running'){throw 'Registered worker must hold the lock and be running.'}
  }else{$lock=[IO.File]::Open((Join-Path $root 'runtime/worker.lock'),'Open','Read','None')}
  $target=Import-RideAutomationLab $config
  if($target.VM.State -ne 'Off' -or (Test-Path -LiteralPath (Join-Path $root 'runtime/blocked.json'))){throw 'Disposable VM must be Off and recovery unblocked.'}
  if(-not $ControllerRunId -and ((Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $config.Name).State -ne 'Ready' -or
    @(Get-ChildItem -LiteralPath (Join-Path $root 'queue/pending') -File).Count -or
    @(Get-ChildItem -LiteralPath (Join-Path $root 'queue/running') -File).Count)){throw 'Idle disposable VM/controller preflight failed.'}
  $machine=Get-LabVM -ComputerName $config.VMName
  if(-not $machine.PSObject.Methods['GetCredential']){throw 'Existing lab guest credential accessor is unavailable.'}
  $credential=$machine.GetCredential((Get-Lab))
  if($credential -isnot [pscredential]){throw 'Existing lab did not provide a guest credential.'}
  $sourceManifest=@(Copy-RideAutomationSnapshot -Source $repo -Destination (Join-Path $output 'source'))
  ConvertTo-Json -InputObject $sourceManifest -Depth 4|Set-Content -LiteralPath (Join-Path $output 'source-manifest.json') -Encoding UTF8
  $revisionRoot=if($ControllerRunId){$config.LocalRepositoryPath}else{$repo}
  $revision=& git -C $revisionRoot rev-parse HEAD
  if($LASTEXITCODE -ne 0 -or $revision -notmatch '^[a-f0-9]{40}$'){throw 'Cannot record the source checkout revision.'}
  @{SourceCommit=$revision;ContentIdentity='Working-tree source-manifest hashes, including uncommitted changes'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $output 'source-context.json') -Encoding UTF8
  $null=New-Item -ItemType Directory -Path (Join-Path $output 'payloads')
  foreach($payload in $payloads){
    $copy=Join-Path (Join-Path $output 'payloads') $payload.FileName
    Copy-Item -LiteralPath $payload.Path -Destination $copy
    if((Get-FileHash -LiteralPath $copy).Hash -ine $payload.Sha256 -or (Get-FileHash -LiteralPath $payload.Path).Hash -ine $payload.Sha256){throw 'Archive changed while staging.'}
  }
  ConvertTo-Json -InputObject @($payloads|Select-Object Id,FileName,Sha256)|Set-Content -LiteralPath (Join-Path $output 'payloads.json') -Encoding UTF8
  $touched=$true
  Restore-VMSnapshot -VMSnapshot $target.Snapshot -Confirm:$false
  Start-VM -VM $target.VM
  $deadline=[datetime]::UtcNow.AddMinutes(5)
  do{
    try{$session=New-PSSession -VMId ([guid]$config.VMId) -Credential $credential -ErrorAction Stop}catch{Start-Sleep -Seconds 3}
  }while(-not $session -and [datetime]::UtcNow -lt $deadline)
  if(-not $session){throw 'PowerShell Direct did not become ready within five minutes.'}
  Invoke-Command -Session $session -ArgumentList $guestBase,$config.VMName {
    param($Base,$Expected)
    if($env:COMPUTERNAME -ine $Expected -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine'){throw 'Guest identity/model mismatch.'}
    $null=New-Item -ItemType Directory -Path $Base
    $null=New-Item -ItemType Directory -Path (Join-Path $Base 'evidence')
  }
  foreach($name in @('source','payloads','payloads.json','source-manifest.json','source-context.json')){
    Copy-Item -LiteralPath (Join-Path $output $name) -Destination $guestBase -ToSession $session -Recurse
  }
  Invoke-Command -Session $session -ArgumentList $guestBase {
    param($Base)
    $manifest=Get-Content -LiteralPath (Join-Path $Base 'source-manifest.json') -Raw|ConvertFrom-Json
    foreach($file in $manifest){
      if((Get-FileHash -LiteralPath (Join-Path (Join-Path $Base 'source') $file.Path)).Hash -ine $file.SHA256){throw 'Guest source digest mismatch.'}
    }
  }
  $job=Invoke-Command -Session $session -AsJob -ArgumentList $guestBase,$config.VMName,$Batch {
    param($Base,$Expected,$SelectedBatch)
    $env:RIDE_INTEGRATION_VM='1'
    $guestFile=if($SelectedBatch -eq 'OfflineCaffeine'){'Invoke-RideOfflineAcceptance.ps1'}else{'Invoke-RidePortableAcceptance.ps1'}
    $script=Join-Path $Base ('source/tests/integration/'+$guestFile)
    $evidence=Join-Path $Base 'evidence'
    & (Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe') -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -ExpectedComputerName $Expected -EvidencePath $evidence -Batch $SelectedBatch -DisposableVm *> (Join-Path $evidence 'acceptance.log')
    if($LASTEXITCODE -ne 0){throw 'Guest portable checks failed; inspect acceptance.log and scenarios.json.'}
  }
  if(-not (Wait-Job $job -Timeout ($TimeoutMinutes*60))){throw 'Guest check execution timed out.'}
  $null=Receive-Job $job -ErrorAction Stop
  $summary=Invoke-Command -Session $session -ArgumentList $guestEvidence {param($Evidence) Get-Content -LiteralPath (Join-Path $Evidence 'summary.json') -Raw|ConvertFrom-Json}
  if($summary.Status -ne 'Passed' -or $summary.Passed -ne $cases.Count){throw 'Guest summary does not establish all selected lifecycle cases.'}
  $result.ToolExecuted=[bool]$summary.ToolExecuted
  $result.FunctionalAcceptance=[string]$summary.FunctionalAcceptance
  $result.Status='Passed'
}catch{$result.Error=$_.Exception.Message}
finally{
  if($job){Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}
  try{
    if($session){
      if(Invoke-Command -Session $session -ArgumentList $guestEvidence {param($Path) Test-Path -LiteralPath $Path}){
        Copy-Item -LiteralPath $guestEvidence -Destination $output -FromSession $session -Recurse
        $result.EvidenceCollected=$true
        $guestSummary=Join-Path $output 'summary.json'
        if(-not (Test-Path -LiteralPath $guestSummary)){$guestSummary=Join-Path $output 'evidence/summary.json'}
        if(Test-Path -LiteralPath $guestSummary){
          $partialSummary=Get-Content -LiteralPath $guestSummary -Raw|ConvertFrom-Json
          $result.ToolExecuted=[bool]$partialSummary.ToolExecuted
          $result.FunctionalAcceptance=[string]$partialSummary.FunctionalAcceptance
        }
      }
    }
  }catch{$result.Status='Failed';$result.Error=[string]$result.Error+'; Collection: '+$_.Exception.Message}
  if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}
  try{
    if($touched){
      Reset-RideAutomationVm $config
      $reset=Import-RideAutomationLab $config
      if($reset.VM.State -ne 'Off'){throw 'Checkpoint recovery did not leave the VM Off.'}
      $result.Cleanup='ResetAndOff'
    }
  }catch{
    $result.Cleanup='Failed';$result.Status='Failed';$result.Error=[string]$result.Error+'; Cleanup: '+$_.Exception.Message
    try{$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'runtime/blocked.json') -Encoding UTF8}catch{$result.Error+='; Failed to persist controller recovery block.'}
  }
  $result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $output 'result.json') -Encoding UTF8
  if($lock){$lock.Dispose()}
}
[pscustomobject]$result
if($result.Status -ne 'Passed'){throw ([string]$result.Error+' Evidence: '+$output)}
