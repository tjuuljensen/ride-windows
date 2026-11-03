<#
.SYNOPSIS
  Validate finite queued OpenSSH Client and RSAT acceptance phases.
.DESCRIPTION
  Binds requests to an expiring activation and registered controller. Selected
  host sources are hash-pinned and held read-only during dispatch. This module
  does not register tasks, access credentials, service Windows or reset a VM.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: 0.1.0. Changelog: Add fixed retained capability queue boundaries.
.LINK
  ../../docs/windows-component-inventory.md
#>
$ErrorActionPreference='Stop'

function ConvertTo-RideCapabilityQueueTime {
  param($Value)
  if($Value -is [datetimeoffset]){return $Value}
  if($Value -is [datetime]){return [datetimeoffset]$Value}
  if($Value -isnot [string]){throw 'Queue time must be an ISO timestamp.'}
  [datetimeoffset]::ParseExact($Value,'o',[Globalization.CultureInfo]::InvariantCulture)
}

function Assert-RideCapabilityQueueActivation {
  <#
  .SYNOPSIS
    Validate an expiring activation against its current registered controller.
  .PARAMETER Activation
    Protected JSON activation record created during attended registration.
  .PARAMETER Configuration
    Existing validated disposable controller configuration.
  .PARAMETER ConfigurationSha256
    Digest of the exact installed controller configuration bytes.
  .OUTPUTS
    None. Throws on configuration, source or time-contract drift.
  #>
  param($Activation,$Configuration,[string]$ConfigurationSha256)
  if($Activation.SchemaVersion -isnot [int] -and $Activation.SchemaVersion -isnot [long]){throw 'Capability activation schema must be an integer.'}
  if($Activation.SchemaVersion -ne 1 -or $Activation.Kind -cne 'ClientCapabilityQueueActivation' -or
     $Activation.ActivationId -isnot [string] -or $Activation.ActivationId -cnotmatch '^[a-f0-9]{32}$' -or
     $Activation.ConfigurationSha256 -cnotmatch '^[A-F0-9]{64}$' -or $Activation.ConfigurationSha256 -cne $ConfigurationSha256){throw 'Capability activation identity or configuration digest differs.'}
  foreach($field in @('Name','HostAccountSid','VMId','CheckpointId','LocalRepositoryPath')){
    if([string]$Activation.$field -cne [string]$Configuration.$field){throw "Capability activation binding differs: $field"}
  }
  if($Configuration.IsDisposable -ne $true -or $Activation.TaskName -cne ($Configuration.Name+'Capabilities')){throw 'Capability activation requires its fixed disposable task.'}
  $created=ConvertTo-RideCapabilityQueueTime $Activation.CreatedAtUtc
  $expires=ConvertTo-RideCapabilityQueueTime $Activation.ExpiresAtUtc
  if($expires -le $created -or ($expires-$created).TotalHours -gt 12){throw 'Capability activation must expire within twelve hours.'}
  if($Activation.ExpectedBuild -isnot [string] -or $Activation.ExpectedBuild -cnotmatch '^\d{5,8}$' -or [long]$Activation.ExpectedBuild -lt 22000 -or
     $Activation.ExpectedEditionId -cnotin @('Professional','ProfessionalN','ProfessionalEducation','ProfessionalEducationN','ProfessionalWorkstation','ProfessionalWorkstationN','Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN') -or
     ($Activation.ExpectedRevision -isnot [int] -and $Activation.ExpectedRevision -isnot [long]) -or $Activation.ExpectedRevision -lt 0 -or $Activation.ExpectedRevision -gt [int]::MaxValue){throw 'Capability activation requires an exact Windows 11 target/revision.'}
  Assert-RideCapabilityQueueSourceManifest $Activation.HostSources
}

function Resolve-RideCapabilityQueueRequest {
  <#
  .SYNOPSIS
    Return parameters for one fixed retained capability phase, without dispatch.
  .PARAMETER Request
    Bounded request object; arbitrary commands, paths and source modes are refused.
  .PARAMETER Activation
    Previously validated protected activation.
  .PARAMETER Now
    Current UTC time; injectable for deterministic source tests.
  .OUTPUTS
    Phase parameters and the fixed admission budget in minutes.
  #>
  param($Request,$Activation,[datetimeoffset]$Now=[datetimeoffset]::UtcNow)
  $allowed=@('SchemaVersion','ActivationId','RequestId','RunId','Family','Phase','Preview','SubmittedAtUtc','ServicingSource')
  foreach($name in $Request.PSObject.Properties.Name){if($name -cnotin $allowed){throw 'Unknown capability queue request field.'}}
  foreach($name in @('ActivationId','RequestId','RunId')){if($Request.$name -isnot [string] -or $Request.$name -cnotmatch '^[a-f0-9]{32}$'){throw 'Invalid capability request identity.'}}
  if(($Request.SchemaVersion -isnot [int] -and $Request.SchemaVersion -isnot [long]) -or $Request.SchemaVersion -ne 1 -or $Request.ActivationId -cne $Activation.ActivationId -or $Request.Preview -isnot [bool]){throw 'Capability request schema or activation differs.'}
  if($Request.Family -isnot [string] -or $Request.Family -cnotin @('OpenSSHClient','RSAT') -or
     $Request.Phase -isnot [string] -or $Request.Phase -cnotin @('Prepare','Lifecycle','Collect','Reset')){throw 'Unknown capability family or phase.'}
  $submitted=ConvertTo-RideCapabilityQueueTime $Request.SubmittedAtUtc
  if($submitted -gt $Now.AddMinutes(1) -or ($Now-$submitted).TotalMinutes -gt 10){throw 'Capability request is stale or from the future.'}
  $created=ConvertTo-RideCapabilityQueueTime $Activation.CreatedAtUtc
  $expires=ConvertTo-RideCapabilityQueueTime $Activation.ExpiresAtUtc
  $budget=switch($Request.Phase){Prepare {60};Lifecycle {45};default {15}}
  if($Now -lt $created.AddMinutes(-1) -or $Now.AddMinutes($budget) -ge $expires){throw 'Capability activation has insufficient time for this bounded phase and recovery margin.'}
  $parameters=@{Phase=$Request.Phase;RunId=$Request.RunId;Confirm=$false;WhatIf=$Request.Preview}
  if($Request.Phase -ceq 'Prepare'){
    if($Request.ServicingSource -isnot [string] -or $Request.ServicingSource -cne 'WindowsUpdate'){throw 'Prepare requires explicit WindowsUpdate acquisition.'}
    $parameters.Family=$Request.Family;$parameters.ServicingSource='WindowsUpdate'
    $parameters.ExpectedBuild=$Activation.ExpectedBuild;$parameters.ExpectedEditionId=$Activation.ExpectedEditionId;$parameters.ExpectedRevision=[int]$Activation.ExpectedRevision
  }elseif($Request.PSObject.Properties['ServicingSource']){throw 'Servicing source selection belongs only to Prepare.'}
  if($Request.Phase -ceq 'Lifecycle'){$parameters.TimeoutSeconds=1800}
  [pscustomobject]@{Module='RIDE.ClientCapabilityVm.psm1';Command='Invoke-RideClientCapabilityVmPhase';Parameters=$parameters;AdmissionBudgetMinutes=$budget}
}

function Assert-RideCapabilityQueueSourceManifest {
  param([object[]]$Manifest)
  $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L
  if($Manifest.Count -lt 8 -or $Manifest.Count -gt 256){throw 'Invalid capability host source count.'}
  foreach($entry in $Manifest){
    if($entry.Path -isnot [string] -or $entry.Path -cnotmatch '^(modules/[A-Za-z0-9_.-]+\.psm1|catalog/operations\.psd1|tests/integration/RIDE\.(ClientCapabilityVm|ClientCapabilityAcceptance|RetainedGuest|TestAutomation)\.psm1)$' -or
       -not $names.Add($entry.Path) -or $entry.Sha256 -cnotmatch '^[A-F0-9]{64}$' -or ($entry.Bytes -isnot [int] -and $entry.Bytes -isnot [long]) -or $entry.Bytes -lt 1 -or $entry.Bytes -gt 8388608){throw 'Invalid or duplicated capability host source entry.'}
    $total+=[long]$entry.Bytes;if($total -gt 16777216){throw 'Capability host sources exceed sixteen MiB.'}
  }
  foreach($required in @('modules/RIDE.Engine.psm1','modules/RIDE.ClientCapability.psm1','modules/RIDE.PrivateFiles.psm1','catalog/operations.psd1','tests/integration/RIDE.ClientCapabilityVm.psm1','tests/integration/RIDE.ClientCapabilityAcceptance.psm1','tests/integration/RIDE.RetainedGuest.psm1','tests/integration/RIDE.TestAutomation.psm1')){
    if(-not $names.Contains($required)){throw 'Required capability host source is missing.'}
  }
}

function Assert-RideCapabilityQueueRegularPath {
  param([string]$Path)
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Capability queue source must be a regular file.'}
  for($ancestor=$item.Directory;$null -ne $ancestor;$ancestor=$ancestor.Parent){if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Capability queue source traverses a reparse point.'}}
  $item
}

function New-RideCapabilityQueueSourceManifest {
  <#
  .SYNOPSIS
    Hash the bounded host dependency set in the registered checkout.
  .PARAMETER Repository
    Exact registered local checkout; never a request-supplied path.
  .OUTPUTS
    Relative path, byte length and SHA-256 rows. No source bytes are returned.
  #>
  param([string]$Repository)
  $paths=@('catalog/operations.psd1','tests/integration/RIDE.ClientCapabilityVm.psm1','tests/integration/RIDE.ClientCapabilityAcceptance.psm1','tests/integration/RIDE.RetainedGuest.psm1','tests/integration/RIDE.TestAutomation.psm1')
  $paths+=@(Get-ChildItem -LiteralPath (Join-Path $Repository 'modules') -File -Filter '*.psm1'|ForEach-Object {'modules/'+$_.Name})
  if($paths.Count -gt 256){throw 'Capability host source count exceeds its bound.'}
  $manifest=@(foreach($path in $paths){
    $item=Assert-RideCapabilityQueueRegularPath (Join-Path $Repository $path)
    if($item.Length -lt 1 -or $item.Length -gt 8388608){throw 'Capability host source size differs.'}
    [pscustomobject]@{Path=$path;Bytes=$item.Length;Sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash}
  })
  Assert-RideCapabilityQueueSourceManifest $manifest
  $manifest
}

function Open-RideCapabilityQueueSourceLease {
  <#
  .SYNOPSIS
    Hold the exact registered host sources read-only through one phase.
  .PARAMETER Repository
    Registered checkout from the protected activation.
  .PARAMETER Manifest
    Protected source digest inventory; extra module files are refused.
  .OUTPUTS
    Disposable FileStream objects. Caller must dispose every lease in finally.
  #>
  param([string]$Repository,[object[]]$Manifest)
  Assert-RideCapabilityQueueSourceManifest $Manifest
  $actual=@(Get-ChildItem -LiteralPath (Join-Path $Repository 'modules') -File -Filter '*.psm1'|ForEach-Object {'modules/'+$_.Name}|Sort-Object)
  $expected=@($Manifest.Path|Where-Object {$_ -clike 'modules/*'}|Sort-Object)
  if(($actual -join "`n") -cne ($expected -join "`n")){throw 'Capability host module inventory changed after activation.'}
  $leases=[Collections.Generic.List[IO.FileStream]]::new()
  try{
    foreach($entry in $Manifest){
      $item=Assert-RideCapabilityQueueRegularPath (Join-Path $Repository $entry.Path)
      $stream=[IO.File]::Open($item.FullName,'Open','Read','Read');$leases.Add($stream)
      $sha=[Security.Cryptography.SHA256]::Create()
      try{$digest=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')}finally{$sha.Dispose()}
      if($stream.Length -ne $entry.Bytes -or $digest -cne $entry.Sha256){throw 'Capability host source changed after activation; no phase dispatched.'}
    }
    $leases.ToArray()
  }catch{foreach($lease in $leases){$lease.Dispose()};throw}
}

Export-ModuleMember -Function Assert-RideCapabilityQueueActivation,Resolve-RideCapabilityQueueRequest,New-RideCapabilityQueueSourceManifest,Open-RideCapabilityQueueSourceLease
