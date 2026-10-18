<#
.SYNOPSIS
  Verify explicit offline portable installation in a disconnected disposable VM.
.DESCRIPTION
  Binds current source and a retained Caffeine archive into a local test bundle.
  Disables guest network adapters, then checks fail-closed preflight, CLI install
  and profile apply, repeat, removal and exact saved recovery. Never runs Caffeine.
.PARAMETER ExpectedComputerName
  Exact disposable guest identity supplied by the checkpoint-backed host runner.
.PARAMETER EvidencePath
  Correlated evidence directory beneath C:\RIDE\PortableAcceptance.
.PARAMETER Batch
  Only OfflineCaffeine is accepted; ValidateSet supplies completion.
.PARAMETER DisposableVm
  Required explicit guest attestation, in addition to environment and identity guards.
.PARAMETER Version
  Print the version before inspecting the platform.
.EXAMPLE
  .\Invoke-RideOfflineAcceptance.ps1 -Version
.INPUTS
  Host-staged pinned archive, source manifest and source-context.json.
.OUTPUTS
  Correlated summary, scenario, network, manifest and saved-state evidence.
.NOTES
  Compatibility: Elevated Windows PowerShell 5.1 in disposable Windows 11 x64.
  Effects: Guest network adapters disabled; owned package/state and test bundle writes.
  Recovery: Saved-run checks; outer runner restores the registered checkpoint.
  Author: RIDE-Windows maintainers. Version: 0.1.1.
  Changelog: 0.1.1: Require a valid positive preflight before negative cases.
    0.1.0: Add disconnected source-bound portable execution acceptance.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$ExpectedComputerName,[string]$EvidencePath,
  [ValidateSet('OfflineCaffeine')][string]$Batch='OfflineCaffeine',[switch]$DisposableVm,[switch]$Version)
if($Version){'0.1.1';return}
$ErrorActionPreference='Stop'
if(-not $DisposableVm -or $env:RIDE_INTEGRATION_VM -ne '1' -or -not $ExpectedComputerName -or $env:COMPUTERNAME -ine $ExpectedComputerName){throw 'Use the attested disposable guest; no workstation integration is permitted.'}
if((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine'){throw 'Virtual-machine identity required.'}
if(-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Guest elevation required.'}
$evidence=[IO.Path]::GetFullPath($EvidencePath)
if($evidence -notmatch '^C:\\RIDE\\PortableAcceptance\\[0-9a-f]{32}\\evidence$'){throw 'Invalid correlated evidence path.'}
$runRoot=Split-Path -Parent $evidence
$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $repo 'modules/RIDE.Engine.psm1') -Force
Import-Module (Join-Path $repo 'modules/RIDE.PackageSelection.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE.PortableAcceptance.psm1') -Force
if((Get-RidePlatform) -ne 'Windows 11' -or -not [Environment]::Is64BitOperatingSystem){throw 'Windows 11 x64 required.'}
$case=@(Get-RidePortableAcceptanceCases (Get-RideCatalog) -Batch OfflineCaffeine)[0]
$op=(Get-RideSingleOperationPlan -Id $case.Id -Action Install -Variant portable).Operation
if($op.PendingAcceptance){throw 'Offline acceptance cannot promote a pending package.'}
$payloads=Get-Content -LiteralPath (Join-Path $runRoot 'payloads.json') -Raw|ConvertFrom-Json
if(@($payloads).Count -ne 1 -or $payloads.Id -ne $op.Id -or $payloads.FileName -cne $op.AssetName -or $payloads.Sha256 -cne $op.ExpectedSha256){throw 'Unexpected offline payload selection.'}
$archive=Join-Path (Join-Path $runRoot 'payloads') $op.AssetName
if((Get-FileHash -LiteralPath $archive).Hash -ine $op.ExpectedSha256){throw 'Offline archive digest mismatch.'}
if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Disconnect guest adapters and verify offline portable execution')){return}
$null=New-Item -ItemType Directory -Path $evidence -Force
$row=[ordered]@{Id=$op.Id;Variant='portable';Status='Failed';Error=$null;Checks=@();RunIds=@();ToolExecuted=$false;NetworkDisconnected=$false;FunctionalAcceptance='NotTested'}
$stateRoot=Join-Path $env:ProgramData 'RIDE/State'
function Assert-Offline($Condition,$Message){if(-not $Condition){throw $Message}}
function State-Fingerprint {
  if(Test-Path -LiteralPath $stateRoot){(@(Get-ChildItem -LiteralPath $stateRoot -File -Recurse|Sort-Object FullName|ForEach-Object {$_.FullName+':'+(Get-FileHash -LiteralPath $_.FullName).Hash}) -join '|')}else{'Absent'}
}
function Saved-OfflineRun($Output){
  $id=($Output|Where-Object {$_ -is [string] -and $_ -match '^Run ID: '}|Select-Object -Last 1)-replace '^Run ID: ',''
  Assert-Offline ($id -match '^[a-f0-9]{32}$') 'No saved run ID returned.'
  $row.RunIds+=@($id);$id
}
try{
  Assert-Offline (-not (Get-RideCurrentState $op).Present) 'Expected original package absence.'
  $bundle=Join-Path $runRoot 'offline-bundle'
  $null=New-Item -ItemType Directory -Path $bundle
  $files=[Collections.Generic.List[object]]::new()
  function Add-BundleFile($Id,$Relative,$Role,$Source){
    $path=Join-Path $bundle $Relative
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    Copy-Item -LiteralPath $Source -Destination $path
    $files.Add([pscustomobject]@{Id=$Id;RelativePath=$Relative;Role=$Role;Length=(Get-Item -LiteralPath $path).Length;Sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()})
  }
  Add-BundleFile runner 'ride/ride.ps1' Engine (Join-Path $repo 'ride.ps1')
  Add-BundleFile catalog 'ride/catalog/operations.psd1' Engine (Join-Path $repo 'catalog/operations.psd1')
  $number=0
  foreach($file in Get-ChildItem -LiteralPath (Join-Path $repo 'modules') -File -Recurse){
    $number++;$relative=$file.FullName.Substring($repo.Length+1).Replace('\','/')
    Add-BundleFile ('module'+$number) ('ride/'+$relative) Engine $file.FullName
  }
  $profileSource=Join-Path $runRoot 'offline-profile.psd1'
  [IO.File]::WriteAllText($profileSource,"@{SchemaVersion=1;Name='Offline acceptance';Operations=@(@{Id='package.caffeine';State='Present';Variant='portable'})}",[Text.UTF8Encoding]::new($false))
  Add-BundleFile profile 'ride/profiles/offline-acceptance.psd1' Profile $profileSource
  Add-BundleFile payload ('payload/'+$op.AssetName) Payload $archive
  $target=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $sourceContext=Get-Content -LiteralPath (Join-Path $runRoot 'source-context.json') -Raw|ConvertFrom-Json
  $engineVersion=& (Join-Path $repo 'ride.ps1') -Version
  $manifest=[ordered]@{SchemaVersion=1;Kind='RideOfflineBundle';BundleId='caffeine-acceptance';BundleVersion='v1';
    Engine=@{Version=$engineVersion;SourceCommit=$sourceContext.SourceCommit;FileIds=@($files|Where-Object Role -eq Engine|ForEach-Object Id)};
    Files=$files.ToArray();ServicingSources=@();
    Artifacts=@(@{Id='caffeine';PackageId=$op.Id;Variant='portable';Version=$op.PackageVersion;Architecture=$op.Architecture;Targets=@('Windows 11');Status='Included';OmissionCode=$null;FileIds=@('payload');DependencyIds=@();OfflineCapability='DeclaredNoNetwork';ProductUri=$op.ProductUri;DownloadUri=$op.DownloadUri;License=$op.License;LicenseUri=$op.LicenseUri});
    Profiles=@(@{Id='acceptance';FileId='profile';Target='Windows 11';Build=[int]$target.CurrentBuildNumber;EditionId=$target.EditionID;Architecture='x64';ArtifactIds=@('caffeine');ServicingSourceIds=@()})}
  $manifestPath=Join-Path $bundle 'manifest.json'
  $manifest|ConvertTo-Json -Depth 15|Set-Content -LiteralPath $manifestPath -Encoding UTF8
  $row.Build=[string]$target.CurrentBuildNumber
  $row.Edition=$target.EditionID
  $adapters=@(Get-NetAdapter -IncludeHidden)
  $adapters|Select-Object Name,InterfaceDescription,Status|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'network-before.json') -Encoding UTF8
  foreach($adapter in $adapters|Where-Object Status -eq Up){$adapter|Disable-NetAdapter -Confirm:$false}
  Start-Sleep -Seconds 2
  Assert-Offline (-not @(Get-NetAdapter -IncludeHidden|Where-Object Status -eq Up).Count) 'Guest still has an Up network adapter.'
  $row.NetworkDisconnected=$true;$row.Checks+=@('DisconnectedAdapters')
  Import-Module (Join-Path $repo 'modules/RIDE.OfflineBundle.psm1') -Force
  $preflight=Test-RideOfflineBundle -Manifest (Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json) -Root $bundle -ProfileId acceptance -CatalogFileId catalog
  $preflight|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $evidence 'positive-preflight.json') -Encoding UTF8
  Assert-Offline ($preflight.SelectedPackageContentComplete -and -not @($preflight.OfflineGates).Count) 'Positive bundle preflight failed; inspect positive-preflight.json before interpreting negative cases.'
  $plan=@(Get-RideSingleOperationPlan -Id $op.Id -Action Install -Variant portable)
  $before=State-Fingerprint
  foreach($negative in @('MissingPayload','CorruptPayloadPin','OmittedPayload','WrongTarget')){
    $bad=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    switch($negative){
      MissingPayload {($bad.Files|Where-Object Id -eq payload).RelativePath='payload/missing.zip'}
      CorruptPayloadPin {($bad.Files|Where-Object Id -eq payload).Sha256='0'*64}
      OmittedPayload {$bad.Artifacts[0].Status='Omitted';$bad.Artifacts[0].OmissionCode='Missing';$bad.Artifacts[0].FileIds=@()}
      WrongTarget {$bad.Profiles[0].Build=[int]$target.CurrentBuildNumber+1}
    }
    $badPath=Join-Path $bundle ($negative+'.json')
    $bad|ConvertTo-Json -Depth 15|Set-Content -LiteralPath $badPath -Encoding UTF8
    $failure=$null
    try{$null=Invoke-RidePlan $plan -OfflineBundle $badPath -OfflineProfileId acceptance -OfflineCatalogFileId catalog -Confirm:$false}catch{$failure=$_.Exception.Message}
    Assert-Offline ([bool]$failure -and (State-Fingerprint) -ceq $before -and -not (Get-RideCurrentState $op).Present) ('Preflight failed to refuse without mutation: '+$negative)
    $row.Checks+=@($negative+'Refused')
    $row[$negative]=$failure
  }
  $cli=Join-Path $repo 'ride.ps1'
  $offline=@{OfflineBundle=$manifestPath;OfflineProfileId='acceptance';OfflineCatalogFileId='catalog'}
  $null=& $cli install $op.Id -Variant portable @offline -WhatIf
  Assert-Offline ((State-Fingerprint) -ceq $before) 'Offline preview changed saved state.'
  $install=Saved-OfflineRun @(& $cli install $op.Id -Variant portable @offline -Confirm:$false)
  Assert-Offline (Test-RideDesiredState $op Present) 'Offline installation failed.'
  $owned=(Get-RideCurrentState $op).Manifest.Files
  Assert-Offline (-not @($owned|Where-Object AuthenticodeStatus -ne NotInspectedOffline).Count) 'Offline installation invoked signature inspection.'
  Assert-Offline ('No changes were needed; no state record was created.' -in @(& $cli install $op.Id -Variant portable @offline -Confirm:$false)) 'Offline repeat was not a no-op.'
  $null=Restore-RideRun $install -Confirm:$false
  Assert-Offline (-not (Get-RideCurrentState $op).Present) 'Offline install absence recovery failed.'
  $row.Checks+=@('InstallPreview','CliInstall','OfflineSignatureInspectionSkipped','RepeatInstall','InstallAbsenceRestore')
  $profilePath=Join-Path $bundle 'ride/profiles/offline-acceptance.psd1'
  $apply=Saved-OfflineRun @(& $cli apply -Profile $profilePath @offline -Confirm:$false)
  Assert-Offline (Test-RideDesiredState $op Present) 'Offline profile apply failed.'
  Assert-Offline ('No changes were needed; no state record was created.' -in @(& $cli apply -Profile $profilePath @offline -Confirm:$false)) 'Offline profile repeat was not a no-op.'
  $remove=Saved-OfflineRun @(Invoke-RidePlan @(Get-RideSingleOperationPlan $op.Id -Action Remove -Variant portable) -Confirm:$false)
  Assert-Offline (-not (Get-RideCurrentState $op).Present) 'Removal failed.'
  $null=Restore-RideRun $remove -Confirm:$false
  Assert-Offline (Test-RideDesiredState $op Present) 'Removal recovery failed.'
  $restored=(Get-RideCurrentState $op).Manifest.Files
  Assert-Offline ((@($owned|Sort-Object RelativePath|ForEach-Object {$_.RelativePath+':'+$_.Sha256}) -join '|') -ceq (@($restored|Sort-Object RelativePath|ForEach-Object {$_.RelativePath+':'+$_.Sha256}) -join '|')) 'Removal recovery changed owned bytes.'
  $null=Restore-RideRun $apply -Confirm:$false
  Assert-Offline (-not (Get-RideCurrentState $op).Present) 'Profile absence recovery failed.'
  Assert-Offline (-not @(Get-NetAdapter -IncludeHidden|Where-Object Status -eq Up).Count) 'Guest network became available during acceptance.'
  $row.Checks+=@('CliProfileApply','RepeatProfileApply','Remove','ExactRemovalRestore','ProfileAbsenceRestore','StillDisconnected')
  $row.FileEvidence=$owned;$row.Status='Passed'
}catch{$row.Error=$_.Exception.Message}
finally{
  Get-NetAdapter -IncludeHidden|Select-Object Name,InterfaceDescription,Status|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'network-after.json') -Encoding UTF8
  if($manifestPath -and (Test-Path -LiteralPath $manifestPath)){Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $evidence 'bundle-manifest.json')}
  if(Test-Path -LiteralPath $stateRoot){
    $null=New-Item -ItemType Directory -Path (Join-Path $evidence 'saved-state') -Force
    Get-ChildItem -LiteralPath $stateRoot|Where-Object Name -NotIn @('Cache','Artifacts')|ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $evidence 'saved-state') -Recurse}
  }
  ConvertTo-Json -InputObject @([pscustomobject]$row) -Depth 15|Set-Content -LiteralPath (Join-Path $evidence 'scenarios.json') -Encoding UTF8
  @{Batch=$Batch;ExpectedCases=1;Completed=1;Passed=[int]($row.Status -eq 'Passed');Status=$row.Status;PayloadExecution=$false;NetworkDisconnected=$row.NetworkDisconnected}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'summary.json') -Encoding UTF8
}
if($row.Status -ne 'Passed'){throw $row.Error}
