<#
.SYNOPSIS
  Check reviewed portable candidates through the real engine in a disposable guest.
.DESCRIPTION
  Uses host-staged pinned archives for preview, install/repeat/remove and saved-run
  restoration. Tests selected files and unowned/modified-file preservation. For
  NTCore batches, also runs 4GB Patch against a generated x86 PE fixture to verify
  its flag, backup collision and recovery behavior. No real target executable is
  opened or changed. SQLiteQuery is file-lifecycle only; it does not open a database
  or launch the application. ImageMagick reports its version and encodes/identifies
  only a generated 1x1 PNG; it does not open user images. GUI or product activation is not claimed. Candidate support
  is enabled only in the guarded guest's in-memory test catalog.
.PARAMETER ExpectedComputerName
  Exact guest name supplied by the host runner.
.PARAMETER EvidencePath
  Fresh run evidence directory under C:\RIDE\PortableAcceptance\<run-id>.
.PARAMETER Batch
  MiTeCViewers, NTCore, AllReviewed, PSScriptTools, SQLiteQuery, MiTeCUtilityFiles,
  SysinternalsSuite, SysinternalsProducts or ImageMagick. Defender-blocked collections
  remain excluded. SysinternalsSuite checks the fixed 164-file snapshot lifecycle;
  SysinternalsProducts checks the nine independently pinned products' file lifecycle
  only and does not execute utilities or accept any EULA.
  NTCore/AllReviewed include synthetic-file 4GB Patch behavior checks.
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
  Prerequisites: Host runner, elevation, RIDE_INTEGRATION_VM=1, pinned archives; ImageMagick also needs the Microsoft x64 v14 runtime.
  Effects: Guest-only RIDE cache, tools folders, saved state and source observations. The ImageMagick test installs the signed Microsoft runtime only when VCOMP140.DLL is absent.
  Recovery: Saved-run checks and the host's pinned checkpoint restoration.
  Author: RIDE-Windows maintainers. Version: 0.6.0.
  Changelog: 0.6.0: Prepare the Microsoft v14 runtime in the disposable guest and record its evidence.
    0.5.0: Add isolated ImageMagick Q16 synthetic PNG feature acceptance.
    0.4.0: Record NTCore functional rejection as failed and retain recovery evidence.
    0.3.0: Add exact Sysinternals Suite snapshot file-lifecycle selection.
    0.2.5: Add isolated MiTeC UUID/certificate-tool file-lifecycle cases.
    0.2.4: Add SQLiteQuery file-lifecycle-only candidate acceptance.
    0.2.3: Probe PSScriptTools runtime dependencies in isolated child processes.
    0.2.2: Test 4GB Patch on an owned synthetic x86 PE fixture.
    0.2.1: Archive saved state to avoid long evidence copy paths.
    0.2.0: Verify all reviewed source members for PSScriptTools.
    0.1.1: Preserve singleton member arrays and record refusal details.
    0.1.0: Add six focused MiTeC/NTCore file lifecycle scenarios.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$ExpectedComputerName,[string]$EvidencePath,
  [ValidateSet('MiTeCViewers','NTCore','AllReviewed','PSScriptTools','SQLiteQuery','MiTeCUtilityFiles','SysinternalsSuite','SysinternalsProducts','ImageMagick')][string]$Batch='AllReviewed',
  [switch]$DisposableVm,[switch]$Version)
if($Version){'0.6.0';return}
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
function Invoke-ImageMagick([string]$Executable,[string[]]$Arguments){
  if(-not [IO.File]::Exists($Executable)){throw 'ImageMagick executable is missing from the selected package.'}
  $start=New-Object Diagnostics.ProcessStartInfo
  $start.FileName=$Executable
  $start.Arguments=(@($Arguments|ForEach-Object {'"'+([string]$_).Replace('"','\"')+'"'}) -join ' ')
  $start.UseShellExecute=$false;$start.CreateNoWindow=$true
  $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  $process=[Diagnostics.Process]::Start($start)
  if(-not $process.WaitForExit(60000)){$process.Kill();$process.WaitForExit();throw 'ImageMagick synthetic feature command exceeded 60 seconds.'}
  $stdout=$process.StandardOutput.ReadToEnd();$stderr=$process.StandardError.ReadToEnd();$process.Refresh()
  if($process.ExitCode -ne 0){throw "ImageMagick exited with code $($process.ExitCode): $($stderr.Trim())"}
  [pscustomobject]@{ExitCode=$process.ExitCode;StdOut=$stdout;StdErr=$stderr}
}
function Initialize-ImageMagickRuntimePrerequisite([string]$EvidenceRoot){
  $dll=Join-Path (Join-Path $env:SystemRoot 'System32') 'vcomp140.dll'
  $installer=$null;$exitCode=$null;$acquisition='AlreadyPresent'
  if(-not (Test-Path -LiteralPath $dll -PathType Leaf)){
    $installer=Join-Path $EvidenceRoot 'vc_redist.x64.exe'
    $uri='https://aka.ms/vc14/vc_redist.x64.exe'
    Invoke-WebRequest -Uri $uri -OutFile $installer -UseBasicParsing -TimeoutSec 120 -MaximumRedirection 10 -ErrorAction Stop
    $installerSignature=Get-AuthenticodeSignature -LiteralPath $installer
    if($installerSignature.Status -ne 'Valid' -or $installerSignature.SignerCertificate.Subject -notmatch '(?i)O=Microsoft Corporation'){throw 'The downloaded Visual C++ Redistributable does not have a valid Microsoft Authenticode signature.'}
    $installerHash=(Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    $install=Start-Process -FilePath $installer -ArgumentList '/install /quiet /norestart' -WindowStyle Hidden -Wait -PassThru
    $exitCode=[int]$install.ExitCode
    if($exitCode -notin @(0,3010)){throw "The Microsoft Visual C++ Redistributable returned exit code $exitCode."}
    $acquisition='DownloadedFromMicrosoftAndInstalled'
    Remove-Item -LiteralPath $installer -Force
    $installer=$null
  }else{$installerHash=$null;$installerSignature=$null}
  if(-not (Test-Path -LiteralPath $dll -PathType Leaf)){throw 'The Microsoft Visual C++ Redistributable did not provide System32\vcomp140.dll.'}
  $dllSignature=Get-AuthenticodeSignature -LiteralPath $dll
  if($dllSignature.Status -ne 'Valid' -or $dllSignature.SignerCertificate.Subject -notmatch '(?i)O=Microsoft Corporation'){throw 'System32\vcomp140.dll does not have a valid Microsoft Authenticode signature.'}
  $file=Get-Item -LiteralPath $dll
  $result=[ordered]@{Status='Passed';Acquisition=$acquisition;InstallerUri=if($acquisition -eq 'DownloadedFromMicrosoftAndInstalled'){'https://aka.ms/vc14/vc_redist.x64.exe'}else{$null};InstallerSha256=$installerHash;InstallerSigner=if($installerSignature){$installerSignature.SignerCertificate.Subject}else{$null};InstallerSignerThumbprint=if($installerSignature){$installerSignature.SignerCertificate.Thumbprint}else{$null};InstallerExitCode=$exitCode;RuntimeFile='System32/vcomp140.dll';RuntimeFileVersion=$file.VersionInfo.FileVersion;RuntimeSha256=(Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant();RuntimeSigner=$dllSignature.SignerCertificate.Subject;RuntimeSignerThumbprint=$dllSignature.SignerCertificate.Thumbprint}
  $result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $EvidenceRoot 'imagemagick-runtime-prerequisite.json') -Encoding UTF8
  [pscustomobject]$result
}
$results=New-Object 'Collections.Generic.List[object]'
$os=Get-CimInstance Win32_OperatingSystem
foreach($case in $cases){
  $row=[ordered]@{Id=$case.Id;Variant=$case.Variant;Status='Failed';Error=$null;Target=$target;Build=$os.BuildNumber;LifecycleRecovery=$false;FunctionalAcceptance='Pending';PrerequisiteAcceptance='NotSelected';PrerequisiteEvidence=$null;RuntimeAcceptance='NotSelected';RuntimeEvidence=$null;ActivationAcceptance='Pending';ToolExecuted=$false;Checks=@();RunIds=@()}
  try{
    if($case.Id -eq 'package.imagemagick-portable-q16'){
      $row.PrerequisiteAcceptance='Running';$row.PrerequisiteEvidence='imagemagick-runtime-prerequisite.json'
      $runtime=Initialize-ImageMagickRuntimePrerequisite $evidence
      $row.PrerequisiteAcceptance=[string]$runtime.Status
      $row.Checks+=@('MicrosoftV14RuntimePrerequisite')
    }
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
    if($case.Id -eq 'package.imagemagick-portable-q16'){
      $relativeFiles=@($state.Manifest.Files|ForEach-Object RelativePath)
      $requiredArchiveFiles=@('magick.exe','LICENSE.txt','NOTICE.txt')
      Assert-True ($relativeFiles.Count -eq 23 -and -not @($requiredArchiveFiles|Where-Object {$_ -notin $relativeFiles}).Count) 'ImageMagick whole-archive ownership or license notices mismatch.'
      $magickFile=@($state.Manifest.Files|Where-Object RelativePath -ceq 'magick.exe')
      Assert-True ($magickFile.Count -eq 1 -and $magickFile[0].AuthenticodeStatus -eq 'Valid' -and $magickFile[0].SignerThumbprint) 'ImageMagick executable signature evidence is missing or invalid.'
      $row.Checks+=@('WholeArchiveOwnership','LicenseAndNoticePresent','PublisherSignature')
      $row.FileEvidence=$state.Manifest.Files
    }else{
      Assert-True ($state.Manifest.Files.Count -eq $files.Count -and -not @($state.Manifest.Files|Where-Object RelativePath -notin $files).Count) 'Owned file selection mismatch.'
    }
    $beforeHashes=@($state.Manifest.Files|Sort-Object RelativePath|ForEach-Object {$_.RelativePath+':'+$_.Sha256})
    $row.FileEvidence=$state.Manifest.Files
    $row.Checks+=@('InstallPreview','Install','ExactMemberSelection')
    if($case.Id -eq 'package.imagemagick-portable-q16'){
      $tool=Join-Path $op.InstallDirectory 'magick.exe'
      $row.ToolExecuted=$true
      $functionalRoot=Join-Path $evidence 'imagemagick-functional'
      $null=New-Item -ItemType Directory -Path $functionalRoot
      $png=Join-Path $functionalRoot 'synthetic-1x1.png'
      $versionResult=Invoke-ImageMagick $tool @('-version')
      Assert-True ($versionResult.StdOut -match 'ImageMagick 7\.1\.2-34' -and $versionResult.StdOut -match 'Q16') 'ImageMagick version or quantum depth differs from the pinned Q16 package.'
      $createResult=Invoke-ImageMagick $tool @('-size','1x1','xc:#123456',$png)
      Assert-True (Test-Path -LiteralPath $png -PathType Leaf) 'ImageMagick did not create the synthetic PNG.'
      $identifyResult=Invoke-ImageMagick $tool @('identify','-format','%m %wx%h',$png)
      Assert-True ($identifyResult.StdOut.Trim() -ceq 'PNG 1x1') 'ImageMagick did not identify the synthetic PNG as 1x1 PNG.'
      $feature=[ordered]@{Status='Passed';VersionOutput=$versionResult.StdOut.Trim();QuantumDepth='Q16';CreateExitCode=$createResult.ExitCode;IdentifyExitCode=$identifyResult.ExitCode;IdentifyOutput=$identifyResult.StdOut.Trim();SyntheticFile='synthetic-1x1.png';SyntheticSha256=(Get-FileHash -LiteralPath $png).Hash.ToLowerInvariant();SyntheticBytes=(Get-Item -LiteralPath $png).Length}
      $feature|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $functionalRoot 'result.json') -Encoding UTF8
      $row.FunctionalAcceptance='Passed';$row.FunctionalEvidence='imagemagick-functional/result.json'
      $row.Checks+=@('PinnedVersionAndQ16','SyntheticPngEncode','SyntheticPngIdentify')
    }
    if($case.Id -eq 'package.ntcore-4gb-patch'){
      $toolRecord=@($state.Manifest.Files|Where-Object RelativePath -ceq '4gb_patch.exe')
      if($toolRecord.Count -ne 1){throw 'Installed package manifest does not contain exactly one 4GB Patch executable.'}
      $row.ToolExecuted=$true
      $functionalEvidence=Join-Path $evidence '4gb-patch-functional'
      $functionalScript=Join-Path $PSScriptRoot 'Invoke-Ride4GbPatchFunctionalAcceptance.ps1'
      $row.FunctionalEvidence='4gb-patch-functional/result.json'
      $row.FunctionalAcceptance='Running'
      try{
        $functional=@(& $functionalScript -ExpectedComputerName $ExpectedComputerName `
          -ToolPath (Join-Path $op.InstallDirectory '4gb_patch.exe') -ExpectedSha256 $toolRecord[0].Sha256 `
          -EvidencePath $functionalEvidence -DisposableVm -Confirm:$false)
        if($functional.Count -ne 1 -or $functional[0].Status -ne 'Passed'){
          $row.FunctionalAcceptance='Failed'
          throw 'Synthetic x86 PE functional acceptance did not pass.'
        }
        $row.FunctionalAcceptance='Passed'
      }catch{
        if($row.FunctionalAcceptance -eq 'Running'){$row.FunctionalAcceptance='Failed'}
        throw
      }
    }
    if($case.Id -eq 'package.psscripttools'){
      $manifestRelative=@($files|Where-Object {$_ -match '^PSScriptTools-[0-9a-f]{40}/PSScriptTools\.psd1$'})
      if($manifestRelative.Count -ne 1){throw 'Installed PSScriptTools manifest selection is ambiguous.'}
      $runtimeEvidence=Join-Path $evidence 'psscripttools-runtime'
      $runtimeScript=Join-Path $PSScriptRoot 'Invoke-RidePSScriptToolsRuntimeAcceptance.ps1'
      try{
        $runtime=@(& $runtimeScript -ExpectedComputerName $ExpectedComputerName `
          -ModulePath (Join-Path $op.InstallDirectory ($manifestRelative[0] -replace '/','\')) `
          -EvidencePath $runtimeEvidence -DisposableVm -Confirm:$false)
        if($runtime.Count -ne 1){throw 'Runtime acceptance did not return one summary.'}
        $row.RuntimeAcceptance=[string]$runtime[0].Status
        $row.RuntimeEvidence='psscripttools-runtime/summary.json'
      }catch{$row.RuntimeAcceptance='Failed';$row.RuntimeErrorClass=$_.Exception.GetType().FullName}
      $row.Checks+=@('RuntimeDependencyAcceptance')
    }
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
  }catch{$row.Error=$_.Exception.Message;if($row.PrerequisiteAcceptance -eq 'Running'){$row.PrerequisiteAcceptance='Failed'}}
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
$runtimeAcceptance=if($Batch -eq 'PSScriptTools'){[string](@($results|Where-Object Id -eq 'package.psscripttools'|Select-Object -First 1).RuntimeAcceptance)}else{'NotSelected'}
$summary=[ordered]@{Batch=$Batch;ExpectedCases=$cases.Count;Completed=$results.Count;Passed=@($results|Where-Object Status -eq 'Passed').Count;Status='Failed';PayloadExecution=$false;ToolExecuted=@($results|Where-Object ToolExecuted -eq $true).Count -gt 0;FunctionalAcceptance='Pending';RuntimeAcceptance=$runtimeAcceptance;ActivationAcceptance='Pending'}
if($Batch -in @('NTCore','AllReviewed')){
  $functionalRows=@($results|Where-Object Id -eq 'package.ntcore-4gb-patch')
  if($functionalRows.Count -eq 1){
    if($functionalRows[0].FunctionalAcceptance -eq 'Failed'){$summary.FunctionalAcceptance='Failed'}
    elseif($functionalRows[0].FunctionalAcceptance -eq 'Passed' -and $summary.Passed -eq $cases.Count){$summary.FunctionalAcceptance='Passed'}
  }
}
if($Batch -eq 'ImageMagick'){
  $functionalRows=@($results|Where-Object Id -eq 'package.imagemagick-portable-q16')
  if($functionalRows.Count -eq 1 -and $functionalRows[0].FunctionalAcceptance -eq 'Passed' -and $summary.Passed -eq $cases.Count){$summary.FunctionalAcceptance='Passed'}
  elseif($functionalRows.Count -eq 1 -and ($functionalRows[0].ToolExecuted -or $functionalRows[0].PrerequisiteAcceptance -eq 'Failed')){$summary.FunctionalAcceptance='Failed'}
}
if($summary.Passed -eq $cases.Count){$summary.Status='Passed'}
if($Batch -eq 'PSScriptTools' -and $summary.Status -eq 'Passed' -and $summary.RuntimeAcceptance -ne 'Passed'){
  $summary.Status=if($summary.RuntimeAcceptance -eq 'Partial'){'Partial'}else{'Failed'}
}
$summary|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'summary.json') -Encoding UTF8
[pscustomobject]$summary
if($summary.Status -ne 'Passed'){throw 'Focused portable acceptance failed; retain evidence before checkpoint recovery.'}
