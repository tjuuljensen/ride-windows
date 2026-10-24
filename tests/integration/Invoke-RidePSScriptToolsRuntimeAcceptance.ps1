<#
.SYNOPSIS
  Test PSScriptTools import and dependency behavior in a disposable Windows VM.
.DESCRIPTION
  Runs fresh Windows PowerShell 5.1 and PowerShell 7 child processes against the
  exact staged module. Import side effects are confined to a run-owned TEMP
  directory. No dependencies are installed and no source is changed.
.PARAMETER ExpectedComputerName
  Exact guest computer name supplied by the checkpoint-backed runner.
.PARAMETER ModulePath
  Full path to the staged PSScriptTools.psd1 manifest.
.PARAMETER EvidencePath
  Fresh child-evidence directory under the correlated RIDE portable run.
.PARAMETER DisposableVm
  Required explicit guest attestation in addition to identity/model checks.
.PARAMETER Mode
  Internal worker mode. Orchestrator is the only mode for normal invocation.
.EXAMPLE
  .\Invoke-RidePSScriptToolsRuntimeAcceptance.ps1 -ExpectedComputerName RIDE-Win11-Test -ModulePath C:\Tools\psscripttools\PSScriptTools-<revision>\PSScriptTools.psd1 -EvidencePath C:\RIDE\PortableAcceptance\<run-id>\evidence\psscripttools-runtime -DisposableVm
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Elevated disposable Windows 11 guest; exact staged PSScriptTools 3.2.0 source.
  Effects: Starts the module's read-only CIM namespace job and writes its fixed-name file only under a unique TEMP directory.
  Recovery: Child processes exit; the runner deletes only its verified file and empty run-owned TEMP directory.
  Author: RIDE-Windows maintainers. Version: 0.1.3.
  Changelog: 0.1.3: Capture child exit codes with a bounded .NET process wrapper.
    0.1.2: Retain child exception messages and exit codes for failed probes.
    0.1.1: Clean up only child-created jobs after every probe outcome.
    0.1.0: Add isolated dependency-present/missing runtime probes.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [string]$ExpectedComputerName,
  [string]$ModulePath,
  [string]$EvidencePath,
  [switch]$DisposableVm,
  [ValidateSet('Orchestrator','Present','MissingDependency')][string]$Mode='Orchestrator',
  [string]$TempPath,
  [string]$ResultPath,
  [switch]$Version
)
if($Version){'0.1.3';return}
$ErrorActionPreference='Stop'
function Assert-RuntimeGuest {
  if(-not $DisposableVm -or $env:RIDE_INTEGRATION_VM -ne '1' -or -not $ExpectedComputerName -or
     $env:COMPUTERNAME -ine $ExpectedComputerName){throw 'Use the attested disposable guest runner; no workstation integration is permitted.'}
  if((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine'){throw 'Disposable virtual-machine identity is required.'}
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Guest elevation is required.'}
}
function Test-ModulePath {
  $resolved=[IO.Path]::GetFullPath($ModulePath)
  if([IO.Path]::GetFileName($resolved) -cne 'PSScriptTools.psd1' -or
     [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($resolved)) -notmatch '^PSScriptTools-[0-9a-f]{40}$' -or
     [IO.Path]::GetFileName([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($resolved))) -cne 'psscripttools'){
    throw 'ModulePath is not the reviewed PSScriptTools snapshot layout.'
  }
  $file=Get-Item -LiteralPath $resolved -Force
  if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Module manifest is not a regular file.'}
  $resolved
}
function Write-WorkerResult([object]$Value) {
  if([IO.File]::Exists($ResultPath) -or [IO.Directory]::Exists($ResultPath)){throw 'Worker result path already exists.'}
  $json=ConvertTo-Json -InputObject $Value -Depth 6
  [IO.File]::WriteAllText($ResultPath,$json,[Text.UTF8Encoding]::new($false))
}
function Clear-RuntimeProbeJobs([int[]]$BaselineJobIds) {
  $newJobs=@(Get-Job|Where-Object {$_.Id -notin $BaselineJobIds})
  foreach($job in $newJobs){
    if($job.State -in @('NotStarted','Running','Blocked','Suspended','Disconnected')){
      Stop-Job -Id ([int]$job.Id) -ErrorAction SilentlyContinue
    }
    Remove-Job -Id ([int]$job.Id) -Force -ErrorAction SilentlyContinue
  }
}
function Remove-EmptyProbeDirectory([string]$Path,[string]$ParentPath) {
  $parent=[IO.Path]::GetFullPath($ParentPath)
  $target=[IO.Path]::GetFullPath($Path)
  if(-not [IO.Directory]::Exists($target)){return $false}
  $item=Get-Item -LiteralPath $target -Force
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
     -not [IO.Path]::GetDirectoryName($target).Equals($parent,[StringComparison]::OrdinalIgnoreCase) -or
     @(Get-ChildItem -LiteralPath $target -Force).Count -ne 0){return $false}
  [IO.Directory]::Delete($target,$false)
  $true
}
function Invoke-RuntimeWorker {
  Assert-RuntimeGuest
  $manifest=Test-ModulePath
  if(-not $TempPath -or -not $ResultPath){throw 'Worker paths are required.'}
  $temp=[IO.Path]::GetFullPath($TempPath)
  $result=[IO.Path]::GetFullPath($ResultPath)
  $evidence=[IO.Path]::GetFullPath($EvidencePath)
  $runRoot=[IO.Path]::GetDirectoryName($temp)
  if($evidence -notmatch '^C:\\RIDE\\PortableAcceptance\\[0-9a-f]{32}\\evidence\\psscripttools-runtime$' -or
     [IO.Path]::GetFileName($runRoot) -notmatch '^[0-9a-f]{32}$' -or
     -not [IO.Path]::GetDirectoryName($runRoot).Equals($evidence,[StringComparison]::OrdinalIgnoreCase) -or
     [IO.Path]::GetFileName($temp) -cne 'temp' -or
     [IO.Path]::GetFileName($result) -cne 'result.json' -or
     -not [IO.Path]::GetDirectoryName($result).Equals($runRoot,[StringComparison]::OrdinalIgnoreCase)){
    throw 'Worker evidence paths must be inside the correlated portable-acceptance root.'
  }
  if([IO.Directory]::Exists($temp) -or [IO.File]::Exists($temp)){throw 'Run-owned TEMP path already exists.'}
  $null=[IO.Directory]::CreateDirectory($temp)
  $tempInfo=Get-Item -LiteralPath $temp -Force
  if(($tempInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
     -not [IO.Path]::GetFullPath($tempInfo.Parent.FullName).Equals([IO.Path]::GetFullPath((Split-Path -Parent $temp)),[StringComparison]::OrdinalIgnoreCase)){
    throw 'Run-owned TEMP directory is not a direct, non-reparse child.'
  }
  $env:TEMP=$temp;$env:TMP=$temp
  $report=[ordered]@{Mode=$Mode;Edition=$PSVersionTable.PSEdition;PowerShellVersion=$PSVersionTable.PSVersion.ToString();Status='Failed';Imported=$false;RequiredModule='Microsoft.PowerShell.Threadjob';RequiredAssembly='System.Drawing';CimEnumerationJob='NotRun';CimNamespaceCount=0;CimFileIsolated=$false;DrawingFunction='NotRun';ThreadJobFunction='NotRun';ErrorClass=$null;ErrorMessage=$null}
  $baselineJobIds=@(Get-Job|ForEach-Object {[int]$_.Id})
  try {
    $cimFile=Join-Path $temp 'CimNamespaceList.txt'
    if($Mode -eq 'MissingDependency'){
      $emptyModules=Join-Path $temp 'empty-modules'
      $null=[IO.Directory]::CreateDirectory($emptyModules)
      $env:PSModulePath=$emptyModules
      $failure=$null
      try{Import-Module -Name $manifest -Force -ErrorAction Stop|Out-Null}catch{$failure=$_.Exception.Message}
      if(-not $failure -or $failure -notmatch 'Microsoft\.PowerShell\.Threadjob' -or [IO.File]::Exists($cimFile)){
        throw 'Import did not fail solely at the missing ThreadJob requirement before module side effects.'
      }
      $report.Status='Passed';$report.ErrorClass='ExpectedMissingRequiredModule';$report.CimFileIsolated=$true
      Write-WorkerResult ([pscustomobject]$report);return 0
    }
    $module=Import-Module -Name $manifest -Force -PassThru -ErrorAction Stop
    if($module.Version.ToString() -ne '3.2.0'){throw 'Imported module version does not match the pinned candidate.'}
    $report.Imported=$true
    $jobs=@(Get-Job|Where-Object Id -NotIn $baselineJobIds)
    if($jobs.Count -lt 1){throw 'Import did not create the reviewed CIM enumeration ThreadJob.'}
    $deadline=[datetime]::UtcNow.AddSeconds(120)
    while(@($jobs|Where-Object State -in @('NotStarted','Running')).Count -gt 0 -and [datetime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 500;$jobs=@($jobs|ForEach-Object {Get-Job -Id $_.Id})}
    if(@($jobs|Where-Object State -ne 'Completed').Count -gt 0){throw 'CIM enumeration job did not complete within two minutes.'}
    if(-not [IO.File]::Exists($cimFile)){throw 'Module did not create the CIM namespace completion file in the isolated TEMP directory.'}
    $lines=@([IO.File]::ReadAllLines($cimFile))
    if($lines.Count -lt 1){throw 'CIM namespace completion file is empty.'}
    $report.CimEnumerationJob='Completed';$report.CimNamespaceCount=$lines.Count;$report.CimFileIsolated=$true
    $colorResult=[string](Convert-HtmlToAnsi '#123456')
    if($colorResult -cne '[38;2;18;52;86m'){throw 'Convert-HtmlToAnsi returned an unexpected RGB sequence.'}
    $report.DrawingFunction='Passed'
    $powerShell=[System.Management.Automation.PowerShell]::Create()
    $null=$powerShell.AddScript("Start-Sleep -Milliseconds 100; 'runtime-fixture'")
    $handle=$powerShell.BeginInvoke()
    if(-not $handle.AsyncWaitHandle.WaitOne(15000)){throw 'Synthetic runspace did not complete.'}
    $cleanupJob=New-RunspaceCleanupJob -Handle $handle -PowerShell $powerShell -SleepInterval 5 -PassThru
    if(-not (Wait-Job -Job $cleanupJob -Timeout 20)){Stop-Job -Job $cleanupJob -ErrorAction SilentlyContinue;throw 'ThreadJob-backed runspace cleanup timed out.'}
    if($cleanupJob.State -ne 'Completed'){throw 'ThreadJob-backed runspace cleanup failed.'}
    $report.ThreadJobFunction='Passed';$report.Status='Passed'
    Write-WorkerResult ([pscustomobject]$report)
    return 0
  }catch{
    $report.ErrorClass=$_.Exception.GetType().FullName
    $report.ErrorMessage=$_.Exception.Message
    Write-WorkerResult ([pscustomobject]$report)
    return 1
  }finally{
    Clear-RuntimeProbeJobs -BaselineJobIds $baselineJobIds
    $expectedFile=Join-Path $temp 'CimNamespaceList.txt'
    if([IO.File]::Exists($expectedFile)){
      $fi=Get-Item -LiteralPath $expectedFile -Force
      if(-not ($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
         [IO.Path]::GetFullPath($fi.DirectoryName).Equals($temp,[StringComparison]::OrdinalIgnoreCase)){
        [IO.File]::Delete($expectedFile)
      }
    }
    $emptyModules=Join-Path $temp 'empty-modules'
    $null=Remove-EmptyProbeDirectory -Path $emptyModules -ParentPath $temp
    $null=Remove-EmptyProbeDirectory -Path $temp -ParentPath $runRoot
  }
}
function Quote-ProcessArgument([string]$Value){'"'+$Value.Replace('"','\"')+'"'}
if($Mode -ne 'Orchestrator'){
  $exitCode=Invoke-RuntimeWorker
  exit $exitCode
}
Assert-RuntimeGuest
$manifest=Test-ModulePath
$evidence=[IO.Path]::GetFullPath($EvidencePath)
if($evidence -notmatch '^C:\\RIDE\\PortableAcceptance\\[0-9a-f]{32}\\evidence\\psscripttools-runtime$'){throw 'Invalid correlated runtime evidence directory.'}
if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Run isolated PSScriptTools dependency acceptance')){return}
$null=[IO.Directory]::CreateDirectory($evidence)
$worker=$PSCommandPath
$editionExecutables=[Collections.Generic.List[object]]::new()
$desktop=Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
if([IO.File]::Exists($desktop)){$editionExecutables.Add([pscustomobject]@{Edition='Desktop';Path=$desktop})}
$core=Get-Command pwsh.exe -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
if($core){$editionExecutables.Add([pscustomobject]@{Edition='Core';Path=$core.Source})}
$results=[Collections.Generic.List[object]]::new()
foreach($edition in @('Desktop','Core')){
  $exe=$editionExecutables|Where-Object Edition -eq $edition|Select-Object -First 1
  if(-not $exe){$results.Add([pscustomobject]@{Mode='Edition';Edition=$edition;Status='Unavailable';ErrorClass='PowerShellEditionNotInstalled'});continue}
  foreach($workerMode in @('Present','MissingDependency')){
    $runRoot=Join-Path $evidence ([guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($runRoot)
    $temp=Join-Path $runRoot 'temp'
    $resultPath=Join-Path $runRoot 'result.json'
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Quote-ProcessArgument $worker),'-ExpectedComputerName',(Quote-ProcessArgument $ExpectedComputerName),'-ModulePath',(Quote-ProcessArgument $manifest),'-EvidencePath',(Quote-ProcessArgument $evidence),'-DisposableVm','-Mode',$workerMode,'-TempPath',(Quote-ProcessArgument $temp),'-ResultPath',(Quote-ProcessArgument $resultPath)) -join ' '
    try{
      $startInfo=[Diagnostics.ProcessStartInfo]::new()
      $startInfo.FileName=$exe.Path;$startInfo.Arguments=$arguments;$startInfo.UseShellExecute=$false;$startInfo.CreateNoWindow=$true
      $process=[Diagnostics.Process]::new();$process.StartInfo=$startInfo
      if(-not $process.Start()){throw 'Runtime child process did not start.'}
      if(-not $process.WaitForExit(150000)){$process.Kill();$process.WaitForExit();throw 'Runtime child process exceeded the 150-second timeout.'}
      $process.Refresh()
      if($null -eq $process.ExitCode){throw 'Runtime child process exited without a readable exit code.'}
      $processExitCode=[int]$process.ExitCode
      if(-not [IO.File]::Exists($resultPath)){throw 'Runtime child did not write a result record.'}
      $child=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
      $child|Add-Member -NotePropertyName ProcessExitCode -NotePropertyValue $processExitCode -Force
      if($processExitCode -ne 0 -or $child.Status -ne 'Passed'){$child.Status='Failed'}
      $results.Add($child)
    }catch{$results.Add([pscustomobject]@{Mode=$workerMode;Edition=$edition;Status='Failed';ErrorClass=$_.Exception.GetType().FullName;ErrorMessage=$_.Exception.Message})}
  }
}
$passCount=@($results|Where-Object Status -eq 'Passed').Count
$status=if($results.Count -eq 4 -and $passCount -eq 4){'Passed'}elseif(@($results|Where-Object Status -eq 'Failed').Count -gt 0){'Failed'}else{'Partial'}
$summary=[pscustomobject]@{SchemaVersion=1;Product='PSScriptTools';Version='3.2.0';Target='Windows 11';Status=$status;ExpectedCases=4;Completed=$results.Count;Passed=$passCount;Results=@($results.ToArray());DependenciesInstalled=$false;SourceImportedOnlyInChildProcesses=$true;TempIsolatedPerChild=$true;CimNamespaceContentsCollected=$false}
[IO.File]::WriteAllText((Join-Path $evidence 'summary.json'),(ConvertTo-Json -InputObject $summary -Depth 8),[Text.UTF8Encoding]::new($false))
$summary
