<#
.SYNOPSIS
  Check reviewed portable candidates through the real engine in a disposable guest.
.DESCRIPTION
  Uses host-staged pinned archives for preview, install/repeat/remove and saved-run
  restoration. Tests selected files and unowned/modified-file preservation. Does
  not launch tools or claim GUI, parsing or real activation acceptance. Candidate
  support is enabled only in the guarded guest's in-memory test catalog.
.PARAMETER ExpectedComputerName
  Exact guest name supplied by the host runner.
.PARAMETER EvidencePath
  Fresh run evidence directory under C:\RIDE\PortableAcceptance\<run-id>.
.PARAMETER Batch
  MiTeCViewers, NTCore, AllReviewed or PSScriptTools; blocked tools are excluded.
.PARAMETER DisposableVm
  Required explicit guest attestation in addition to identity/model/elevation checks.
.PARAMETER Version
  Print the version without importing modules or querying Windows.
.EXAMPLE
  .\Invoke-RidePortableAcceptance.ps1 -Version
.INPUTS
  Host-staged catalog and payloads.json in the run directory.
.OUTPUTS
  Per-scenario JSON plus ZIP archives of saved engine state under EvidencePath.
.NOTES
  Compatibility: Windows PowerShell 5.1 on a disposable Windows 11 x64 guest.
  Prerequisites: Host runner, elevation, RIDE_INTEGRATION_VM=1, pinned archives.
  Effects: Guest-only RIDE cache, tools folders, saved state and source observations.
  Recovery: Saved-run checks and the host's pinned checkpoint restoration.
  Author: RIDE-Windows maintainers. Version: 0.2.1.
  Changelog: 0.2.1: Archive saved state to avoid long evidence copy paths.
    0.2.0: Verify all reviewed source members for PSScriptTools.
    0.1.1: Preserve singleton member arrays and record refusal details.
    0.1.0: Add six focused MiTeC/NTCore file lifecycle scenarios.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$ExpectedComputerName,[string]$EvidencePath,
  [ValidateSet('MiTeCViewers','NTCore','AllReviewed','PSScriptTools')][string]$Batch='AllReviewed',
  [switch]$DisposableVm,[switch]$Version)
if($Version){'0.2.1';return}
$ErrorActionPreference='Stop'
if(-not $DisposableVm -or $env:RIDE_INTEGRATION_VM -ne '1' -or -not $ExpectedComputerName -or
   $env:COMPUTERNAME -ine $ExpectedComputerName){throw 'Use the attested disposable guest runner; no workstation integration is permitted.'}
if((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine'){throw 'Disposable virtual-machine identity is required.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Guest elevation is required.'}
$evidence=[IO.Path]::GetFullPath($EvidencePath)
if($evidence -notmatch '^C:\\RIDE\\PortableAcceptance\\[0-9a-f]{32}\\evidence$'){throw 'Invalid correlated guest evidence directory.'}
$runRoot=Split-Path -Parent $evidence
$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $repo 'modules/RIDE.Engine.psm1') -Force
Import-Module (Join-Path $repo 'modules/RIDE.PackageSelection.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE.PortableAcceptance.psm1') -Force
$target=Get-RidePlatform
if($target -ne 'Windows 11' -or -not [Environment]::Is64BitOperatingSystem){throw 'This reviewed acceptance batch requires Windows 11 x64.'}
$catalog=Get-RideCatalog
$cases=@(Get-RidePortableAcceptanceCases -Catalog $catalog -Batch $Batch)
$payloads=Get-Content -LiteralPath (Join-Path $runRoot 'payloads.json') -Raw|ConvertFrom-Json
$payloads=@($payloads)
$ids=@($cases.Id|Sort-Object -Unique)
if($payloads.Count -ne $ids.Count -or @($payloads.Id|Sort-Object -Unique).Count -ne $ids.Count){throw 'Unexpected staged payload selection.'}
foreach($id in $ids){
  $op=($cases|Where-Object Id -eq $id|Select-Object -First 1).Operation
  $p=@($payloads|Where-Object Id -ceq $id)
  if($p.Count -ne 1 -or $p[0].Sha256 -cne $op.ExpectedSha256 -or $p[0].FileName -cne $op.AssetName){throw 'Staged archive identity mismatch.'}
  $path=Join-Path (Join-Path $runRoot 'payloads') $op.AssetName
  if((Get-FileHash -LiteralPath $path).Hash -ine $op.ExpectedSha256){throw 'Staged archive digest mismatch.'}
}
if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,"Run $Batch portable lifecycle acceptance")){return}
$null=New-Item -ItemType Directory -Path $evidence -Force
# Enable only the fixed candidates in this process, never in the source catalog.
foreach($op in $catalog.Operations|Where-Object Id -in $ids){$op.SupportedTargets=@($target);$op.PendingAcceptance=$false}
& (Get-Module RIDE.Engine) {param($c) $script:RideLibraryContext=@{Catalog=$c}} $catalog
function Saved-RunId($Output){
  $id=($Output|Where-Object {$_ -is [string] -and $_ -match '^Run ID: '}|Select-Object -Last 1)-replace '^Run ID: ',''
  if($id -notmatch '^[0-9a-f]{32}$'){throw 'Engine did not return a saved run ID.'};$id
}
function Assert-True($Condition,$Message){if(-not $Condition){throw $Message}}
$results=New-Object 'Collections.Generic.List[object]'
$os=Get-CimInstance Win32_OperatingSystem
foreach($case in $cases){
  $row=[ordered]@{Id=$case.Id;Variant=$case.Variant;Status='Failed';Error=$null;Target=$target;Build=$os.BuildNumber;LifecycleRecovery=$false;FunctionalAcceptance='Pending';ActivationAcceptance='Pending';ToolExecuted=$false;Checks=@();RunIds=@()}
  try{
    $plan=@(Get-RideSingleOperationPlan -Id $case.Id -Action Install -Variant $case.Variant)
    $op=$plan[0].Operation
    Assert-True (-not (Get-RideCurrentState $op).Present) 'Expected original package absence.'
    $files=@($case.ExpectedFiles)
    # Cache only the exact declared archive. Resolution remains the real provider path.
    $cache=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('RIDE/State/Cache/'+$op.PackageId+'/'+$op.PackageVersion)
    $null=New-Item -ItemType Directory -Path $cache -Force
    Copy-Item -LiteralPath (Join-Path (Join-Path $runRoot 'payloads') $op.AssetName) -Destination (Join-Path $cache $op.AssetName)
    Assert-True ((Get-FileHash -LiteralPath (Join-Path $cache $op.AssetName)).Hash -ieq $op.ExpectedSha256) 'Cache digest mismatch.'
    $null=Invoke-RidePlan $plan -WhatIf -Confirm:$false
    Assert-True (-not (Get-RideCurrentState $op).Present) 'Install preview changed presence.'
    $installId=Saved-RunId @(Invoke-RidePlan $plan -Confirm:$false);$row.RunIds+=@($installId)
    $state=Get-RideCurrentState $op
    Assert-True (Test-RideDesiredState $op Present) 'Install failed desired-state check.'
    Assert-True ($state.Manifest.Files.Count -eq $files.Count -and -not @($state.Manifest.Files|Where-Object RelativePath -notin $files).Count) 'Owned file selection mismatch.'
    $beforeHashes=@($state.Manifest.Files|Sort-Object RelativePath|ForEach-Object {$_.RelativePath+':'+$_.Sha256})
    $row.FileEvidence=$state.Manifest.Files
    $row.Checks+=@('InstallPreview','Install','ExactMemberSelection')
    $repeat=@(Invoke-RidePlan $plan -Confirm:$false)
    Assert-True ('No changes were needed; no state record was created.' -in $repeat) 'Repeat install was not idempotent.'
    $row.Checks+=@('RepeatInstall')
    $userFile=Join-Path $op.InstallDirectory 'ride-unowned.lic'
    [IO.File]::WriteAllText($userFile,'Synthetic preservation fixture; not an activation key.')
    $remove=@(Get-RideSingleOperationPlan -Id $case.Id -Action Remove -Variant $case.Variant)
    $null=Invoke-RidePlan $remove -WhatIf -Confirm:$false
    Assert-True (Test-RideDesiredState $op Present) 'Remove preview changed presence.'
    $removeId=Saved-RunId @(Invoke-RidePlan $remove -Confirm:$false);$row.RunIds+=@($removeId)
    Assert-True (-not (Get-RideCurrentState $op).Present) 'Removal did not establish absence.'
    Assert-True ('No changes were needed; no state record was created.' -in @(Invoke-RidePlan $remove -Confirm:$false)) 'Repeat removal was not idempotent.'
    $null=Restore-RideRun -RunId $removeId -WhatIf -Confirm:$false
    Assert-True (-not (Get-RideCurrentState $op).Present) 'Restore preview changed absence.'
    $null=Restore-RideRun -RunId $removeId -Confirm:$false
    Assert-True (Test-RideDesiredState $op Present) 'Removal recovery failed.'
    $restored=Get-RideCurrentState $op
    $afterHashes=@($restored.Manifest.Files|Sort-Object RelativePath|ForEach-Object {$_.RelativePath+':'+$_.Sha256})
    Assert-True (($beforeHashes -join '|') -ceq ($afterHashes -join '|')) 'Restored owned hashes differ.'
    Assert-True ([IO.File]::ReadAllText($userFile) -ceq 'Synthetic preservation fixture; not an activation key.') 'Unowned content changed.'
    $row.Checks+=@('RemovePreview','Remove','RepeatRemove','RestorePreview','ExactRemovalRestore','UnownedPreservation')
    $null=Restore-RideRun -RunId $installId -Confirm:$false
    Assert-True (-not (Get-RideCurrentState $op).Present) 'Original absence recovery failed.'
    Assert-True (Test-Path -LiteralPath $userFile) 'Original absence recovery removed unowned content.'
    $row.Checks+=@('OriginalAbsenceRestore')
    # A real unowned executable collision must remain unadopted.
    $collision=Join-Path $op.InstallDirectory $files[0]
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $collision) -Force
    [IO.File]::WriteAllText($collision,'Unowned collision fixture.')
    $refused=$false
    try{$null=Invoke-RidePlan $plan -Confirm:$false}catch{$row.CollisionRefusal=$_.Exception.Message;$refused=$_.Exception.Message -match 'collision'}
    Assert-True ($refused -and [IO.File]::ReadAllText($collision) -ceq 'Unowned collision fixture.') 'Unowned collision was not refused/preserved.'
    Remove-Item -LiteralPath $collision -Force
    $row.Checks+=@('UnownedCollisionRefusal')
    $id=Saved-RunId @(Invoke-RidePlan $plan -Confirm:$false);$row.RunIds+=@($id)
    $modified=Join-Path $op.InstallDirectory $files[0]
    [IO.File]::WriteAllText($modified,'Modified owned fixture.')
    $refused=$false
    try{$null=Invoke-RidePlan $plan -Confirm:$false}catch{$row.ModifiedRefusal=$_.Exception.Message;$refused=$_.Exception.Message -match 'modified managed'}
    Assert-True $refused 'Modified managed replacement was not refused.'
    $null=Invoke-RidePlan $remove -Confirm:$false
    Assert-True ([IO.File]::ReadAllText($modified) -ceq 'Modified owned fixture.') 'Modified owned content was deleted.'
    $row.Checks+=@('ModifiedReplacementRefusal','ModifiedRemovalPreservation')
    # Delete only this run's synthetic modified/unowned fixtures, never recursively.
    Remove-Item -LiteralPath $modified,$userFile -Force
    $row.LifecycleRecovery=$true;$row.Status='Passed'
  }catch{$row.Error=$_.Exception.Message}
  $results.Add([pscustomobject]$row)
  ConvertTo-Json -InputObject @($results.ToArray()) -Depth 15|Set-Content -LiteralPath (Join-Path $evidence 'scenarios.json') -Encoding UTF8
  if($row.Status -ne 'Passed'){break}
}
$stateRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RIDE/State'
if(Test-Path -LiteralPath $stateRoot){
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $null=New-Item -ItemType Directory -Path (Join-Path $evidence 'saved-state') -Force
  Get-ChildItem -LiteralPath $stateRoot -Force|Where-Object Name -NotIn @('Cache','Artifacts')|ForEach-Object {
    if($_.PSIsContainer){
      # Preserve the full state tree without extending every member's filesystem path.
      $archive=Join-Path (Join-Path $evidence 'saved-state') ($_.Name+'.zip')
      [IO.Compression.ZipFile]::CreateFromDirectory($_.FullName,$archive)
      $zip=[IO.Compression.ZipFile]::OpenRead($archive)
      try {
        $expected=@(Get-ChildItem -LiteralPath $_.FullName -File -Recurse -Force).Count
        if(@($zip.Entries|Where-Object Name).Count -ne $expected){throw 'Saved-state archive file count mismatch.'}
      }finally{$zip.Dispose()}
    }else{Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $evidence 'saved-state')}
  }
}
Copy-Item -LiteralPath (Join-Path $repo 'catalog/artifact-observations.json') -Destination (Join-Path $evidence 'artifact-observations.json')
$summary=[ordered]@{Batch=$Batch;ExpectedCases=$cases.Count;Completed=$results.Count;Passed=@($results|Where-Object Status -eq 'Passed').Count;Status='Failed';PayloadExecution=$false;FunctionalAcceptance='Pending';ActivationAcceptance='Pending'}
if($summary.Passed -eq $cases.Count){$summary.Status='Passed'}
$summary|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'summary.json') -Encoding UTF8
[pscustomobject]$summary
if($summary.Status -ne 'Passed'){throw 'Focused portable acceptance failed; retain evidence before checkpoint recovery.'}
