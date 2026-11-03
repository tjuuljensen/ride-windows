<#
.SYNOPSIS
  Check reviewed portable candidates through the real engine in a disposable guest.
.DESCRIPTION
  Uses host-staged pinned archives for preview, install/repeat/remove and saved-run
  restoration. Tests selected files and unowned/modified-file preservation. For
  NTCore batches, also runs 4GB Patch against a generated x86 PE fixture to verify
  its flag, backup collision and recovery behavior. No real target executable is
  opened or changed. MiTeC executables, including SQLiteQuery, receive bounded
  startup checks without supplied documents, databases or account settings.
  System Information tests MSIX/MSIX64 startup; GetSys helpers remain file-only.
  ImageMagick reports its version and encodes/identifies
  only a generated 1x1 PNG; it does not open user images. NTCoreAdditional stages
  Driver List x64/x86 and Rebel.NET without launching them. MiTeCMailHistoryViewers
  checks lifecycle and bounded startup without selecting user stores.
  GUI or product activation is not claimed. Candidate support
  is enabled only in the guarded guest's in-memory test catalog.
  MiTeC, Sysinternals Suite/Products, NTCore and PSScriptTools batches require active
  Defender and no detection since guest boot,
  including staging; record sanitized before/after evidence without exclusions.
  RegRipper and Rufus use the same file-only lifecycle and Defender boundary;
  the remaining MiTeC viewer, development, network and system batches select
  fixed variants and observe startup without supplying user application data.
  No registry hive, external drive or media-write action is selected.
  WindowsFirewallNotifier stages all 531 reviewed pinned files with Defender
  observation and exact recovery; WFN is not launched and firewall policy is unchanged.
  WinPmem uses the same Defender boundary for its single-file lifecycle, without
  executing its userspace program or loading any embedded driver.
.PARAMETER ExpectedComputerName
  Exact guest name supplied by the host runner.
.PARAMETER EvidencePath
  Fresh run evidence directory under C:\RIDE\PortableAcceptance\<run-id>.
.PARAMETER Batch
  WindowsFirewallNotifier is the pinned x64 Nightly file lifecycle only.
  MiTeCDevelopment selects both DFM Editor generations, Task Manager DeLuxe
  architectures and Interbase Query architectures. MiTeCNetworkUtilities selects
  Network Scanner architectures, DirList and Network Meter. MiTeCSystemViewers
  selects OLE/COM, Registry Recovery, SMBIOS, File Analyzer, Icon Explorer and
  Structured Storage Viewer. MiTeC cases include bounded process startup;
  deeper feature acceptance is deferred to v3.1 by the 2026-11-03 decision.
  MiTeCViewers, MiTeCAnalysisTools, MiTeCSystemAndTelephony, NTCore, NTCoreAdditional, MiTeCMailHistoryViewers, AllReviewed,
  PSScriptTools, SQLiteQuery, MiTeCUtilityFiles,
  SysinternalsSuite, SysinternalsProducts, ImageMagick, RawCopy, WinPmem, RegRipper or Rufus. Defender-blocked collections
  remain excluded. SysinternalsSuite checks the fixed 164-file snapshot lifecycle;
  SysinternalsProducts checks the nine independently pinned products' file lifecycle
  only and does not execute utilities or accept any EULA. RegRipper and Rufus
  check fixed owned files, exact recovery and Defender observations without
  opening tools, user data or external media.
  NTCore/AllReviewed include synthetic-file 4GB Patch behavior checks.
  RawCopy runs only against one generated 4096-byte NTFS fixture with TCP output,
  filesystem-info output and raw-directory listing disabled; it never reads evidence.
  WinPmem checks exact owned-file staging and recovery only; it does not execute
  the acquisition program or load or unload its driver.
  MiTeCSystemAndTelephony stages exact System Information eXtra and TAPI Monitor files and observes primary-application startup; no report command, provider configuration or call control is selected.
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
  Effects: Guest-only RIDE cache, tools folders, saved state and source observations. ImageMagick may install the signed Microsoft runtime when absent. RawCopy uses only one generated fixture and removes it after a passing check.
  Recovery: Saved-run checks and the host's pinned checkpoint restoration.
  Author: RIDE-Windows maintainers. Version: 0.22.2.
  Changelog: 0.22.2: Select MSIX primary startup and run untested TAPI Monitor first.
    0.22.1: Run the known Scanner x86 startup failure last within its fixed batch.
    0.22.0: Add hash-bound MiTeC startup smoke checks; defer features to v3.1.
    0.21.0: Require Defender observations for WinPmem file-only acceptance.
    0.20.0: Add fixed WFN file lifecycle; no firewall changes.
    0.19.0: Add fixed remaining MiTeC lifecycle selections.
    0.18.0: Add Defender observations to NTCore and PSScriptTools acceptance.
    0.17.0: Add fixed RegRipper and Rufus lifecycle/Defender scenarios.
    0.16.0: Require Defender evidence for fixed NTCoreAdditional and
    SysinternalsProducts file-lifecycle batches.
    0.15.0: Require the same Defender evidence for Sysinternals Suite.
    0.14.0: Record read-only Defender evidence for MiTeC lifecycle acceptance.
    0.13.0: Add an exact WinPmem file-staging-only batch.
    0.12.0: Add System Information eXtra and TAPI Monitor lifecycle selection.
    0.11.0: Add the MiTeC EXE Explorer and HexEdit lifecycle batch.
    0.10.0: Run RawCopy only against its generated synthetic NTFS fixture.
    0.9.0: Resolve guest package payloads from the staged bundle, not stripped host paths.
    0.8.0: Add MiTeC mail/history viewer file-lifecycle-only acceptance.
    0.7.0: Add file-lifecycle-only NTCore Driver List and Rebel.NET acceptance.
    0.6.1: Select the requested package from prerequisite-expanded plans.
    0.6.0: Prepare the Microsoft v14 runtime in the disposable guest and record its evidence.
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
  [ValidateSet('MiTeCViewers','MiTeCAnalysisTools','MiTeCSystemAndTelephony','NTCore','NTCoreAdditional','MiTeCMailHistoryViewers','AllReviewed','PSScriptTools','SQLiteQuery','MiTeCUtilityFiles','SysinternalsSuite','SysinternalsProducts','ImageMagick','RawCopy','WinPmem','RegRipper','Rufus','MiTeCDevelopment','MiTeCNetworkUtilities','MiTeCSystemViewers','WindowsFirewallNotifier')][string]$Batch='AllReviewed',
  [switch]$DisposableVm,[switch]$Version)
if($Version){'0.22.2';return}
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
if($Batch -eq 'MiTeCNetworkUtilities'){
  # The Nov 3 x86 crash must not keep the two other tools permanently untested.
  # Retain all four cases and fail the batch if the final x86 startup still fails.
  $cases=@($cases|Where-Object {-not ($_.Id -ceq 'package.mitec-network-scanner' -and $_.Variant -ceq 'x86')})+@($cases|Where-Object {$_.Id -ceq 'package.mitec-network-scanner' -and $_.Variant -ceq 'x86'})
}
if($Batch -eq 'MiTeCSystemAndTelephony'){
  $cases=@($cases|Where-Object Id -CEQ 'package.mitec-tapi-monitor')+@($cases|Where-Object Id -CEQ 'package.mitec-system-information')
}
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
$defenderRequired=@($ids|Where-Object {$_ -like 'package.mitec-*'}).Count -gt 0 -or 'package.sysinternals-suite' -in $ids -or $Batch -in @('NTCore','NTCoreAdditional','PSScriptTools','SysinternalsProducts','RegRipper','Rufus','WindowsFirewallNotifier','WinPmem')
$defenderSince=$null
if($defenderRequired){
  Import-Module (Join-Path $PSScriptRoot 'RIDE.DefenderAcceptance.psm1') -Force
  $defenderSince=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
  if(-not $defenderSince){throw 'Guest boot time unavailable for Defender acceptance.'}
  $defenderBefore=Get-RideDefenderAcceptanceObservation -Since $defenderSince
  $defenderBefore|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $evidence 'defender-before.json') -Encoding UTF8
  if(-not $defenderBefore.Passed){throw 'Defender preflight failed; preserve evidence and stop without changing exclusions.'}
}
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
    $targetPlanItems=@($plan|Where-Object {$_.Operation.Id -ceq $case.Id})
    if($targetPlanItems.Count -ne 1){throw "Expanded install plan does not contain exactly one target operation '$($case.Id)'."}
    $op=$targetPlanItems[0].Operation
    Assert-True (-not (Get-RideCurrentState $op).Present) 'Expected original package absence.'
    $files=@($case.ExpectedFiles)
    # Cache each exact package in the dependency-expanded plan; the guest uses no network fallback.
    foreach($plannedPackage in @($plan|Where-Object {$_.Operation.Kind -eq 'Package' -and $_.State -eq 'Present'})){
      $plannedOperation=$plannedPackage.Operation
      $plannedPayload=@($payloads|Where-Object Id -ceq $plannedOperation.Id)
      if($plannedPayload.Count -eq 0){
        if(-not (Get-RideCurrentState $plannedOperation).Present){throw "No exact staged payload exists for planned prerequisite '$($plannedOperation.Id)'."}
        continue
      }
      if($plannedPayload.Count -ne 1 -or $plannedPayload[0].FileName -cne $plannedOperation.AssetName -or $plannedPayload[0].Sha256 -cne $plannedOperation.ExpectedSha256){throw "Staged payload identity mismatch: $($plannedOperation.Id)"}
      $cache=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('RIDE/State/Cache/'+$plannedOperation.PackageId+'/'+$plannedOperation.PackageVersion)
      $null=New-Item -ItemType Directory -Path $cache -Force
      $cachedPayload=Join-Path $cache $plannedOperation.AssetName
      $stagedPayload=Get-RidePortableAcceptanceStagedPayloadPath -RunRoot $runRoot -FileName $plannedOperation.AssetName
      Copy-Item -LiteralPath $stagedPayload -Destination $cachedPayload
      Assert-True ((Get-FileHash -LiteralPath $cachedPayload).Hash -ieq $plannedOperation.ExpectedSha256) "Cache digest mismatch: $($plannedOperation.Id)"
    }
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
    if($case.Id -like 'package.mitec-*'){
      Import-Module (Join-Path $PSScriptRoot 'RIDE.FastTrackStartup.psm1') -Force
      $startupSelection=Get-RideFastTrackStartupSelection -PackageId $case.Id -Files $state.Manifest.Files
      $startupFiles=@($startupSelection.Executables)
      if($startupSelection.DeferredExecutables.Count){$row.StartupDeferred=[pscustomobject]@{Files=$startupSelection.DeferredExecutables;Reason=$startupSelection.DeferredReason}}
      $row.StartupEvidence=@(foreach($startupFile in $startupFiles){
        Invoke-RideFastTrackStartup -ExecutablePath (Join-Path $op.InstallDirectory $startupFile.RelativePath) -ExpectedSha256 $startupFile.Sha256
      })
      $row.ToolExecuted=$true
      $row.Checks+=@('BoundedStartupNoErrorObserved')
      $row.FunctionalAcceptance='Deferred to v3.1 by user decision; startup only'
    }
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
    if($case.Id -eq 'package.rawcopy'){
      $toolRecord=@($state.Manifest.Files|Where-Object RelativePath -match '(^|/)RawCopy64\.exe$')
      if($toolRecord.Count -ne 1){throw 'Installed package manifest does not contain exactly one RawCopy64.exe.'}
      $row.ToolExecuted=$true
      $functionalRoot=Join-Path $evidence 'rawcopy-synthetic'
      $null=New-Item -ItemType Directory -Path $functionalRoot
      $functionalScript=Join-Path $PSScriptRoot 'Invoke-RideRawCopySyntheticAcceptance.ps1'
      $row.FunctionalEvidence='rawcopy-synthetic/result.json'
      $row.FunctionalAcceptance='Running'
      try{
        $functional=@(& $functionalScript -ExpectedComputerName $ExpectedComputerName `
          -ExecutablePath (Join-Path $op.InstallDirectory ($toolRecord[0].RelativePath -replace '/','\')) `
          -EvidencePath (Join-Path $functionalRoot 'result.json') -Confirm:$false)
        if($functional.Count -ne 1 -or $functional[0].Status -ne 'Passed'){
          $row.FunctionalAcceptance='Failed'
          throw 'Synthetic NTFS file behavior acceptance did not pass.'
        }
        $row.FunctionalAcceptance='Passed'
        $row.Checks+=@('PinnedExecutableDigest','SyntheticOnlyNtfsCopy','TcpOutputDisabled','SourceUnchanged','OutputHashMatch','FixtureCleanup')
      }catch{
        if($row.FunctionalAcceptance -eq 'Running'){$row.FunctionalAcceptance='Failed'}
        throw
      }
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
      $modulePrerequisite=@($plan|Where-Object {$_.Operation.Id -ceq $op.PrerequisitePackageId})
      if($modulePrerequisite.Count -ne 1 -or -not (Get-RideCurrentState $modulePrerequisite[0].Operation).Present){throw 'The planned ThreadJob module prerequisite is not installed for runtime acceptance.'}
      $runtimeEvidence=Join-Path $evidence 'psscripttools-runtime'
      $runtimeScript=Join-Path $PSScriptRoot 'Invoke-RidePSScriptToolsRuntimeAcceptance.ps1'
      try{
        $runtime=@(& $runtimeScript -ExpectedComputerName $ExpectedComputerName `
          -ModulePath (Join-Path $op.InstallDirectory ($manifestRelative[0] -replace '/','\')) `
          -ThreadJobModulePath $modulePrerequisite[0].Operation.InstallDirectory `
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
  }catch{$row.Error=$_.Exception.Message;if($_.Exception.Data.Contains('RideStartupEvidence')){$row.StartupEvidence=$_.Exception.Data['RideStartupEvidence'];$row.ToolExecuted=($null -ne $row.StartupEvidence.ProcessId)};if($row.PrerequisiteAcceptance -eq 'Running'){$row.PrerequisiteAcceptance='Failed'}}
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
if($Batch -eq 'RawCopy'){
  $functionalRows=@($results|Where-Object Id -eq 'package.rawcopy')
  if($functionalRows.Count -eq 1 -and $functionalRows[0].FunctionalAcceptance -eq 'Passed' -and $summary.Passed -eq $cases.Count){$summary.FunctionalAcceptance='Passed'}
  elseif($functionalRows.Count -eq 1 -and $functionalRows[0].ToolExecuted){$summary.FunctionalAcceptance='Failed'}
}
if($summary.Passed -eq $cases.Count){$summary.Status='Passed'}
if($defenderRequired){
  $summary.DefenderAcceptance='Failed'
  try{
    $defenderAfter=Get-RideDefenderAcceptanceObservation -Since $defenderSince
    $defenderAfter|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $evidence 'defender-after.json') -Encoding UTF8
    if($defenderAfter.Passed){$summary.DefenderAcceptance='Passed'}else{$summary.Status='Failed'}
  }catch{$summary.Status='Failed';$summary.DefenderError=$_.Exception.Message}
}
if($Batch -eq 'PSScriptTools' -and $summary.Status -eq 'Passed' -and $summary.RuntimeAcceptance -ne 'Passed'){
  $summary.Status=if($summary.RuntimeAcceptance -eq 'Partial'){'Partial'}else{'Failed'}
}
$summary|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'summary.json') -Encoding UTF8
[pscustomobject]$summary
if($summary.Status -ne 'Passed'){throw 'Focused portable acceptance failed; retain evidence before checkpoint recovery.'}
