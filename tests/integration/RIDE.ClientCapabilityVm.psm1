<#
.SYNOPSIS
  Dispatch fixed client capability phases to the registered disposable VM.
.DESCRIPTION
  Uses the existing retained-guest lease, registered lab credential and PowerShell
  Direct. Stages bounded engine/catalog/profile sources, runs only the selected
  OpenSSHClient or RSAT scenario, and exports evidence before an explicit reset.
  An interrupted lifecycle without its terminal result prevents reset.
.NOTES
  Compatibility: Native elevated Windows PowerShell 5.1 x64 host with Hyper-V.
  Prerequisites: Existing protected controller registration and an idle Off VM.
  No task registration, UAC, arbitrary command callback or automatic failure reset.
  This source-prepared route is not installed in the overnight broker.
  Version: 0.1.0. Changelog: Add retained client capability host phases.
.LINK
  ../../docs/windows-component-inventory.md
#>
$ErrorActionPreference='Stop'
$script:automation=Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -PassThru -ErrorAction Stop
$script:retained=Import-Module (Join-Path $PSScriptRoot 'RIDE.RetainedGuest.psm1') -PassThru -ErrorAction Stop
$script:private=Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -PassThru -ErrorAction Stop
$script:clientCapability=Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.ClientCapability.psm1') -PassThru -ErrorAction Stop

function Get-RideCapabilityVmContext {
  param([string]$Path,[bool]$Mutation)
  & $script:retained {param($p,$m) Get-RideRetainedConfiguration $p $m} $Path $Mutation
}
function Write-RideCapabilityVmRecord {
  param([string]$Path,$Record)
  & $script:retained {param($p,$r) Write-RideRetainedRecord $p $r} $Path $Record
}
function Read-RideCapabilityVmRecord {
  param([string]$Path)
  & $script:retained {param($p) Read-RideRetainedRecord $p} $Path
}
function New-RideCapabilityVmDirectory {
  param([string]$Path)
  $null=& $script:private {param($p) Resolve-RidePrivateFilePath $p} $Path
  if(Test-Path -LiteralPath $Path){throw 'Retained capability directory already exists.'}
  $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  foreach($sid in @('S-1-5-32-544','S-1-5-18')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
  $directory=[IO.DirectoryInfo]::new($Path)
  if($PSVersionTable.PSEdition -eq 'Desktop'){$directory.Create($acl)}else{[IO.FileSystemAclExtensions]::Create($directory,$acl)}
  if((Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm('Access,Owner') -cne $acl.GetSecurityDescriptorSddlForm('Access,Owner')){throw 'Retained directory permissions differ.'}
}
function Get-RideCapabilityVmHash {
  param([byte[]]$Bytes)
  $hash=[Security.Cryptography.SHA256]::Create()
  try{[BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','')}finally{$hash.Dispose()}
}
function Assert-RideCapabilityVmSourceManifest {
  param($Manifest)
  $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L
  if(@($Manifest).Count -lt 5 -or @($Manifest).Count -gt 256){throw 'Capability source count differs.'}
  foreach($entry in $Manifest){
    if($entry.Path -cnotmatch '^(modules/[A-Za-z0-9_.-]+\.psm1|profiles/[A-Za-z0-9_.-]+\.psd1|catalog/operations\.psd1|tests/integration/RIDE\.ClientCapabilityAcceptance\.psm1)$' -or -not $names.Add($entry.Path) -or $entry.Bytes -lt 1 -or $entry.Bytes -gt 8388608 -or $entry.Sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Invalid capability source manifest entry.'}
    $total+=$entry.Bytes;if($total -gt 16777216){throw 'Capability sources exceed sixteen MiB.'}
  }
  foreach($required in @('modules/RIDE.Engine.psm1','modules/RIDE.ClientCapability.psm1','modules/RIDE.PrivateFiles.psm1','catalog/operations.psd1','tests/integration/RIDE.ClientCapabilityAcceptance.psm1')){if(-not $names.Contains($required)){throw 'Required capability source is missing.'}}
}
function New-RideCapabilityVmSnapshot {
  param([string]$Repository,[string]$Directory)
  $paths=@('catalog/operations.psd1','tests/integration/RIDE.ClientCapabilityAcceptance.psm1')
  foreach($folder in @('modules','profiles')){
    $null=& $script:private {param($p) Resolve-RidePrivateFilePath $p} (Join-Path (Join-Path $Repository $folder) '_probe')
    $filter=if($folder -ceq 'modules'){'*.psm1'}else{'*.psd1'}
    $paths+=@(Get-ChildItem -LiteralPath (Join-Path $Repository $folder) -File -Filter $filter|ForEach-Object {$folder+'/'+$_.Name})
  }
  if($paths.Count -gt 256){throw 'Capability source count exceeds its bound.'}
  New-RideCapabilityVmDirectory $Directory
  $manifest=@();$total=0L
  foreach($relative in $paths|Sort-Object){
    $path=Join-Path $Repository $relative
    $null=& $script:private {param($p) Resolve-RidePrivateFilePath $p} $path
    if((Get-Item -LiteralPath $path).Length -gt 8388608){throw 'Capability source exceeds its bound.'}
    $bytes=[IO.File]::ReadAllBytes($path);$total+=$bytes.Length
    if($bytes.Length -lt 1 -or $bytes.Length -gt 8388608 -or $total -gt 16777216){throw 'Capability snapshot exceeds its bound.'}
    $destination=Join-Path $Directory $relative;$null=New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force
    $stream=[IO.File]::Open($destination,'CreateNew','Write','None');try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $manifest+=@([pscustomobject]@{Path=$relative;Bytes=$bytes.Length;Sha256=(Get-RideCapabilityVmHash $bytes)})
  }
  Assert-RideCapabilityVmSourceManifest $manifest
  $manifest
}
function Get-RideCapabilityVmPayload {
  param([string]$Directory,$Manifest)
  Assert-RideCapabilityVmSourceManifest $Manifest
  foreach($entry in $Manifest){
    $path=Join-Path $Directory $entry.Path
    $null=& $script:private {param($p) Resolve-RidePrivateFilePath $p} $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.Bytes){throw 'Retained source size changed.'}
    $bytes=[IO.File]::ReadAllBytes($path)
    if($bytes.Length -ne $entry.Bytes -or (Get-RideCapabilityVmHash $bytes) -cne $entry.Sha256){throw 'Retained source bytes changed.'}
    [pscustomobject]@{Path=$entry.Path;Bytes=$entry.Bytes;Sha256=$entry.Sha256;Content=[Convert]::ToBase64String($bytes)}
  }
}
function Get-RideCapabilityVmCredential {
  param($Configuration)
  & $script:automation {
    param($config)
    $machine=Get-LabVM -ComputerName $config.VMName
    if(-not $machine.PSObject.Methods['GetCredential']){throw 'Registered guest credential accessor is unavailable.'}
    $credential=$machine.GetCredential((Get-Lab))
    if($credential -isnot [pscredential]){throw 'Registered lab did not return a guest credential.'}
    $credential
  } $Configuration
}

# This fixed scriptblock is the only remote dispatch target. Queue inputs cannot
# supply PowerShell source, command names, VM identities or guest filesystem roots.
$script:capabilityRemote={
  param($Action,$Descriptor,$Payload)
  $ErrorActionPreference='Stop'
  if($Action -cnotin @('Ready','Prepare','Lifecycle','Collect') -or $Descriptor.RunId -cnotmatch '^[a-f0-9]{32}$' -or $Descriptor.LeaseId -cnotmatch '^[a-f0-9]{32}$' -or $Descriptor.Family -cnotin @('OpenSSHClient','RSAT') -or $Descriptor.ServicingSource -cne 'WindowsUpdate'){throw 'Invalid fixed capability dispatch.'}
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $system=Get-CimInstance Win32_ComputerSystem
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{$admin=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}finally{$identity.Dispose()}
  if($env:COMPUTERNAME -ine $Descriptor.VMName -or $system.Manufacturer -cne 'Microsoft Corporation' -or $system.Model -cne 'Virtual Machine' -or -not $admin -or -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -cne 'AMD64' -or [string]$version.CurrentBuildNumber -cne $Descriptor.ExpectedBuild -or $version.EditionID -cne $Descriptor.ExpectedEditionId -or [int]$version.UBR -ne $Descriptor.ExpectedRevision -or $version.InstallationType -cne 'Client'){throw 'Capability guest identity differs.'}
  $context=[pscustomobject]@{ComputerName=$env:COMPUTERNAME;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;Revision=[int]$version.UBR}
  if($Action -ceq 'Ready'){return $context}
  $root=Join-Path $env:ProgramData ('RIDE-CapabilityAcceptance/'+$Descriptor.RunId)
  $source=Join-Path $root 'source';$evidence=Join-Path $root 'evidence';$resultPath=Join-Path (Join-Path $evidence $Descriptor.RunId) 'result.json'
  function AssertLocalPath([string]$Path){for($node=[IO.DirectoryInfo]::new($Path);$null -ne $node;$node=$node.Parent){if($node.Exists -and ($node.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Guest path has a reparse ancestor.'}}}
  AssertLocalPath $root
  if($Action -ceq 'Prepare'){
    if(Test-Path -LiteralPath $root){throw 'Guest request directory already exists.'}
    if(@($Payload).Count -ne @($Descriptor.Manifest).Count -or @($Payload).Count -gt 256){throw 'Guest source selection differs.'}
    $null=New-Item -ItemType Directory -Path $source,$evidence -Force
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L
    foreach($entry in $Payload){
      $expected=@($Descriptor.Manifest|Where-Object Path -CEQ $entry.Path)
      if($expected.Count -ne 1 -or $entry.Path -cnotmatch '^(modules/[A-Za-z0-9_.-]+\.psm1|profiles/[A-Za-z0-9_.-]+\.psd1|catalog/operations\.psd1|tests/integration/RIDE\.ClientCapabilityAcceptance\.psm1)$' -or -not $seen.Add($entry.Path) -or $entry.Bytes -ne $expected[0].Bytes -or $entry.Sha256 -cne $expected[0].Sha256 -or $entry.Content.Length -gt 11184812){throw 'Invalid staged capability source.'}
      $bytes=[Convert]::FromBase64String($entry.Content);$total+=$bytes.Length
      if($bytes.Length -ne $entry.Bytes -or $bytes.Length -lt 1 -or $bytes.Length -gt 8388608 -or $total -gt 16777216){throw 'Guest source size differs.'}
      $path=Join-Path $source $entry.Path;$null=New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force
      $stream=[IO.File]::Open($path,'CreateNew','Write','None');try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      if((Get-FileHash -LiteralPath $path).Hash -cne $entry.Sha256){throw 'Guest source digest differs.'}
    }
    Import-Module (Join-Path $source 'modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Descriptor|ConvertTo-Json -Depth 10 -Compress))
    $stream=New-RidePrivateFileStream -Path (Join-Path $root 'session.json') -Scope Machine;try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    return [pscustomobject]@{RunId=$Descriptor.RunId;Family=$Descriptor.Family;Status='Prepared';Context=$context;SourceCount=@($Payload).Count}
  }
  if(-not (Test-Path -LiteralPath (Join-Path $root 'session.json'))){throw 'Prepared capability session is missing.'}
  foreach($entry in $Descriptor.Manifest){
    $path=Join-Path $source $entry.Path;AssertLocalPath (Split-Path $path -Parent)
    $file=Get-Item -LiteralPath $path -Force
    if($file.Length -ne $entry.Bytes -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.Sha256){throw 'Guest snapshot changed.'}
  }
  Import-Module (Join-Path $source 'modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop
  $savedBytes=Read-RidePrivateFileBytes -Path (Join-Path $root 'session.json') -Scope Machine -MaximumBytes 1048576
  $saved=[Text.UTF8Encoding]::new($false,$true).GetString($savedBytes)|ConvertFrom-Json
  foreach($field in @('RunId','LeaseId','VMId','VMName','CheckpointId','ConfigurationSha256','Family','ServicingSource','ExpectedBuild','ExpectedEditionId','ExpectedRevision')){if($saved.$field -cne $Descriptor.$field){throw 'Guest session binding differs.'}}
  $intent=Join-Path $evidence 'lifecycle-intent.json'
  if($Action -ceq 'Lifecycle'){
    if(Test-Path -LiteralPath $intent){throw 'A lifecycle was already admitted; collect its result without retrying.'}
    $env:RIDE_TEST_GUEST='1';$env:RIDE_INTEGRATION_VM='1';$env:RIDE_TEST_RUN_ID=$Descriptor.RunId
    Import-Module (Join-Path $source 'tests/integration/RIDE.ClientCapabilityAcceptance.psm1') -ErrorAction Stop
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($saved|Select-Object RunId,LeaseId,Family|ConvertTo-Json -Compress))
    $stream=New-RidePrivateFileStream -Path $intent -Scope Machine;try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    return Invoke-RideClientCapabilityAcceptance -Family $Descriptor.Family -RunId $Descriptor.RunId -ExpectedComputerName $context.ComputerName -ExpectedBuild $Descriptor.ExpectedBuild -ExpectedEditionId $Descriptor.ExpectedEditionId -ExpectedRevision $Descriptor.ExpectedRevision -ServicingSource WindowsUpdate -EvidenceRoot $evidence -DisposableVm -Confirm:$false
  }
  $terminal=$null
  if(Test-Path -LiteralPath $resultPath){$terminalBytes=Read-RidePrivateFileBytes -Path $resultPath -Scope Machine -MaximumBytes 1048576;$terminal=[Text.UTF8Encoding]::new($false,$true).GetString($terminalBytes)|ConvertFrom-Json;if($terminal.RunId -cne $Descriptor.RunId -or $terminal.Family -cne $Descriptor.Family -or $terminal.Status -cnotin @('Passed','Failed')){throw 'Terminal capability result differs.'}}
  $files=@();$total=0L;$pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($evidence)
  while($pending.Count){
    foreach($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force){
      if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Guest evidence contains a reparse point.'}
      if($item.PSIsContainer){$pending.Enqueue($item.FullName);if($pending.Count -gt 512){throw 'Guest evidence directories exceed their bound.'};continue}
      $relative=$item.FullName.Substring($evidence.Length+1).Replace('\','/')
      if($files.Count -ge 512 -or $relative -cnotmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*\.json$' -or @($relative -split '/'|Where-Object {$_ -in @('.','..')}).Count -or $item.Length -gt 4194304){throw 'Guest evidence path or size differs.'}
      $bytes=[IO.File]::ReadAllBytes($item.FullName);$total+=$bytes.Length
      if($bytes.Length -gt 4194304 -or $total -gt 33554432){throw 'Guest evidence exceeds thirty-two MiB.'}
      $files+=@([pscustomobject]@{Path=$relative;Bytes=$bytes.Length;Sha256=(Get-FileHash -LiteralPath $item.FullName).Hash;Content=[Convert]::ToBase64String($bytes)})
    }
  }
  [pscustomobject]@{RunId=$Descriptor.RunId;Family=$Descriptor.Family;Status='Collected';Context=$context;LifecycleAdmitted=(Test-Path -LiteralPath $intent);TerminalResultPresent=($null -ne $terminal);TerminalStatus=$(if($terminal){$terminal.Status}else{$null});Files=$files}
}

function Invoke-RideCapabilityVmRemote {
  param($Configuration,[pscredential]$Credential,[string]$Action,$Descriptor,$Payload,[int]$TimeoutSeconds=180)
  $job=Invoke-Command -VMId ([guid]$Configuration.VMId) -Credential $Credential -ScriptBlock $script:capabilityRemote -ArgumentList $Action,$Descriptor,$Payload -AsJob -ErrorAction Stop
  try{
    if(-not (Wait-Job $job -Timeout $TimeoutSeconds)){throw 'Capability phase timed out; servicing may still be running. Retain the VM and lease.'}
    $result=@(Receive-Job $job -ErrorAction Stop)
    if($job.State -ne 'Completed' -or $result.Count -ne 1){throw 'Capability phase did not return one completed result.'}
    $result[0]
  }finally{Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}
}
function Wait-RideCapabilityVmReady {
  param($Configuration,$Credential,$Descriptor)
  $deadline=[datetime]::UtcNow.AddMinutes(3)
  do{try{return Invoke-RideCapabilityVmRemote $Configuration $Credential Ready $Descriptor $null 15}catch{if([datetime]::UtcNow -ge $deadline){throw 'Capability guest readiness failed within three minutes.'};Start-Sleep -Seconds 2}}while($true)
}
function Export-RideCapabilityVmEvidence {
  param($Configuration,$Credential,$Descriptor,[string]$Store)
  $collected=Invoke-RideCapabilityVmRemote $Configuration $Credential Collect $Descriptor $null 180
  if($collected.RunId -cne $Descriptor.RunId -or $collected.Family -cne $Descriptor.Family -or $collected.Status -cne 'Collected' -or @($collected.Files).Count -gt 512){throw 'Capability export identity differs.'}
  if($collected.Context.ComputerName -ine $Descriptor.VMName -or $collected.Context.Build -cne $Descriptor.ExpectedBuild -or $collected.Context.EditionId -cne $Descriptor.ExpectedEditionId -or $collected.Context.Revision -ne $Descriptor.ExpectedRevision -or $collected.LifecycleAdmitted -isnot [bool] -or $collected.TerminalResultPresent -isnot [bool]){throw 'Capability export target or terminal metadata differs.'}
  $directory=Join-Path $Store ('export.'+[guid]::NewGuid().ToString('N'));New-RideCapabilityVmDirectory $directory
  $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L;$manifest=@()
  foreach($entry in $collected.Files){
    if($entry.Path -cnotmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*\.json$' -or @($entry.Path -split '/'|Where-Object {$_ -in @('.','..')}).Count -or -not $seen.Add($entry.Path) -or $entry.Bytes -lt 0 -or $entry.Bytes -gt 4194304 -or $entry.Content.Length -gt 5592408){throw 'Capability export entry differs.'}
    $bytes=[Convert]::FromBase64String($entry.Content);$total+=$bytes.Length
    if($bytes.Length -ne $entry.Bytes -or $total -gt 33554432 -or (Get-RideCapabilityVmHash $bytes) -cne $entry.Sha256){throw 'Capability export bytes differ.'}
    $path=Join-Path $directory $entry.Path;$null=New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force
    $stream=[IO.File]::Open($path,'CreateNew','Write','None');try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if((Get-FileHash -LiteralPath $path).Hash -cne $entry.Sha256){throw 'Export readback differs.'}
    $manifest+=@($entry|Select-Object Path,Bytes,Sha256)
  }
  if($collected.LifecycleAdmitted -ne $seen.Contains('lifecycle-intent.json') -or $collected.TerminalResultPresent -ne $seen.Contains($Descriptor.RunId+'/result.json')){throw 'Capability export terminal files differ from metadata.'}
  if($collected.TerminalResultPresent){
    $terminal=Get-Content -LiteralPath (Join-Path $directory ($Descriptor.RunId+'/result.json')) -Raw|ConvertFrom-Json
    if($terminal.RunId -cne $Descriptor.RunId -or $terminal.Family -cne $Descriptor.Family -or $terminal.Status -cnotin @('Passed','Failed') -or $terminal.Status -cne $collected.TerminalStatus){throw 'Exported capability result differs.'}
  }
  $receipt=[pscustomobject]@{SchemaVersion=1;Kind='CapabilityVmExport';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Family=$Descriptor.Family;Context=$collected.Context;LifecycleAdmitted=$collected.LifecycleAdmitted;TerminalResultPresent=$collected.TerminalResultPresent;TerminalStatus=$collected.TerminalStatus;Files=$manifest}
  Write-RideCapabilityVmRecord (Join-Path $directory 'export-receipt.json') $receipt
  [pscustomobject]@{Verified=$true;Path=$directory;FileCount=$manifest.Count;LifecycleAdmitted=$receipt.LifecycleAdmitted;TerminalResultPresent=$receipt.TerminalResultPresent;TerminalStatus=$receipt.TerminalStatus}
}

function Invoke-RideClientCapabilityVmPhase {
  <#
  .SYNOPSIS
    Prepare, execute, collect or reset one fixed retained capability scenario.
  .PARAMETER Phase
    Prepare, Lifecycle, Collect or Reset. Reset requires a fresh verified export.
  .PARAMETER ConfigurationPath
    Protected installed controller configuration for the registered host account.
  .PARAMETER RunId
    Fresh request for Prepare; the same owned request for later phases.
  .PARAMETER Family
    Prepare-only OpenSSHClient or RSAT selection.
  .PARAMETER ServicingSource
    Prepare-only explicit WindowsUpdate acquisition.
  .PARAMETER ExpectedBuild
    Prepare-only exact Windows 11 build.
  .PARAMETER ExpectedEditionId
    Prepare-only exact client edition; RSAT requires Pro/Enterprise family.
  .PARAMETER ExpectedRevision
    Prepare-only exact update build revision.
  .PARAMETER TimeoutSeconds
    Lifecycle job budget, 30-3600 seconds. Timeout retains the VM/lease.
  .EXAMPLE
    Invoke-RideClientCapabilityVmPhase -Phase Collect -ConfigurationPath '<installed-configuration>' -RunId '<request-id>' -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 phase report; only Lifecycle can establish LifecyclePassed.
  .NOTES
    Requires existing elevation; never requests UAC. Source preparation does not
    install a queued route. Interrupted preparation/reset needs retained-state
    inspection; this initial route deliberately refuses an Off-guest reset retry.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidateSet('Prepare','Lifecycle','Collect','Reset')][string]$Phase,
    [Parameter(Mandatory)][string]$ConfigurationPath,[Parameter(Mandatory)][ValidatePattern('(?-i)^[a-f0-9]{32}$')][string]$RunId,
    [ValidateSet('OpenSSHClient','RSAT')][string]$Family,[ValidateSet('WindowsUpdate')][string]$ServicingSource,
    [ValidatePattern('^[0-9]{5,8}$')][string]$ExpectedBuild,
    [ValidateSet('Professional','ProfessionalN','ProfessionalEducation','ProfessionalEducationN','ProfessionalWorkstation','ProfessionalWorkstationN','Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')][string]$ExpectedEditionId,
    [ValidateRange(0,2147483647)][int]$ExpectedRevision,[ValidateRange(30,3600)][int]$TimeoutSeconds=1800)
  foreach($name in @('Phase','Family','ServicingSource','ExpectedEditionId')){
    if($PSBoundParameters.ContainsKey($name)){
      $values=@($MyInvocation.MyCommand.Parameters[$name].Attributes|Where-Object {$_ -is [Management.Automation.ValidateSetAttribute]})[0].ValidValues
      $selected=$PSBoundParameters[$name];$canonical=@($values|Where-Object {$_ -ieq $selected})[0]
      switch($name){Phase {$Phase=$canonical};Family {$Family=$canonical};ServicingSource {$ServicingSource=$canonical};ExpectedEditionId {$ExpectedEditionId=$canonical}}
    }
  }
  $prepareNames=@('Family','ServicingSource','ExpectedBuild','ExpectedEditionId','ExpectedRevision')
  if($Phase -ceq 'Prepare'){foreach($name in $prepareNames){if(-not $PSBoundParameters.ContainsKey($name)){throw "Prepare requires explicit $name."}};if([long]$ExpectedBuild -lt 22000){throw 'Prepare requires Windows 11.'}}
  elseif(@($prepareNames|Where-Object {$PSBoundParameters.ContainsKey($_)}).Count){throw 'Source and target selection belong only to Prepare.'}
  if($Phase -ceq 'Prepare' -and $Family -ceq 'RSAT'){
    & $script:clientCapability {param($edition) Assert-RideRsatCapabilityContext ([pscustomobject]@{Architecture='AMD64';EditionId=$edition})} $ExpectedEditionId
  }
  $context=Get-RideCapabilityVmContext $ConfigurationPath (-not $WhatIfPreference)
  $repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\')
  if([IO.Path]::GetFullPath($context.Configuration.LocalRepositoryPath).TrimEnd('\') -ine $repository){throw 'Use the registered checkout for capability dispatch.'}
  if(-not $PSCmdlet.ShouldProcess($context.Configuration.VMName,"Run explicit retained capability $Phase phase")){return [pscustomobject]@{SchemaVersion=1;RunId=$RunId;Phase=$Phase;Status='Preview';LifecyclePassed=$false}}
  if($Phase -ceq 'Prepare'){$null=New-RideRetainedGuestHold -ConfigurationPath $ConfigurationPath -RunId $RunId -Confirm:$false}
  $owned=Open-RideRetainedGuestPhase -ConfigurationPath $ConfigurationPath -RunId $RunId
  $store=Join-Path $context.Root ('retained-capability-'+$RunId);$release=$false;$ready=$false
  $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='CapabilityVmPhase';RunId=$RunId;Phase=$Phase;Status='Failed';Stage='Ownership';Error=$null;RecoveryRequired=$true;LifecyclePassed=$false;GuestResult=$null;EvidenceExport=$null}
  try {
    if($owned.Context.ConfigurationSha256 -cne $context.ConfigurationSha256){throw 'Controller configuration changed under phase ownership.'}
    if($Phase -ceq 'Prepare'){
      New-RideCapabilityVmDirectory $store
      $manifest=@(New-RideCapabilityVmSnapshot $repository (Join-Path $store 'snapshot'))
      $descriptor=[pscustomobject][ordered]@{SchemaVersion=1;Kind='CapabilityVmSession';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;VMId=$owned.Hold.VMId;VMName=$owned.Hold.VMName;CheckpointId=$owned.Hold.CheckpointId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;Family=$Family;ServicingSource=$ServicingSource;ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;ExpectedRevision=$ExpectedRevision;Manifest=$manifest}
      Write-RideCapabilityVmRecord (Join-Path $store 'session.json') $descriptor
    }else{
      $descriptor=Read-RideCapabilityVmRecord (Join-Path $store 'session.json')
      if($descriptor.SchemaVersion -ne 1 -or $descriptor.Kind -cne 'CapabilityVmSession'){throw 'Capability session schema differs.'}
      foreach($field in @('RunId','LeaseId','VMId','VMName','CheckpointId','ConfigurationSha256')){if($descriptor.$field -cne $owned.Hold.$field){throw 'Capability session ownership differs.'}}
    }
    $credential=Get-RideCapabilityVmCredential $context.Configuration
    if($Phase -ceq 'Prepare'){
      $payload=@(Get-RideCapabilityVmPayload (Join-Path $store 'snapshot') $descriptor.Manifest)
      if($owned.Target.VM.State -ne 'Off'){throw 'Preparation requires the reserved VM to remain Off.'}
      $report.Stage='InitialCheckpoint';Write-RideCapabilityVmRecord (Join-Path $store 'prepare-intent.json') $report
      Restore-VMSnapshot -VMSnapshot $owned.Target.Snapshot -Confirm:$false -ErrorAction Stop
      Start-VM -VM $owned.Target.VM -ErrorAction Stop|Out-Null
    }elseif($owned.Target.VM.State -ne 'Running'){throw 'Retained capability phases require a running guest; inspect interrupted preparation/reset without releasing the hold.'}
    $report.Stage='GuestReadiness';$null=Wait-RideCapabilityVmReady $context.Configuration $credential $descriptor;$ready=$true
    if($Phase -cin @('Prepare','Lifecycle')){
      if($Phase -ceq 'Lifecycle'){$null=@(Get-RideCapabilityVmPayload (Join-Path $store 'snapshot') $descriptor.Manifest);$payload=$null}
      $report.Stage=$Phase;$budget=if($Phase -ceq 'Lifecycle'){$TimeoutSeconds}else{180}
      $guest=Invoke-RideCapabilityVmRemote $context.Configuration $credential $Phase $descriptor $payload $budget
      $report.GuestResult=$guest
      if($guest.RunId -cne $RunId -or $guest.Family -cne $descriptor.Family){throw 'Capability guest result identity differs.'}
      if($Phase -ceq 'Prepare' -and ($guest.Status -cne 'Prepared' -or $guest.SourceCount -ne @($descriptor.Manifest).Count)){throw 'Capability preparation did not complete.'}
      if($Phase -ceq 'Lifecycle' -and ($guest.Kind -cne 'ClientCapabilityAcceptance' -or $guest.Status -cne 'Passed' -or $guest.LifecyclePassed -ne $true -or @($guest.Checks).Count -ne 7 -or $guest.RecoveryRequired -ne $false)){throw 'Capability lifecycle did not pass; retain its evidence and engine runs.'}
      $report.Status=$guest.Status
    }else{$report.Status='Collected'}
    $report.Stage='EvidenceExport';$report.EvidenceExport=Export-RideCapabilityVmEvidence $context.Configuration $credential $descriptor $store
    if($report.EvidenceExport.Verified -ne $true){throw 'Capability evidence export was not verified.'}
    if($Phase -ceq 'Lifecycle' -and ($report.EvidenceExport.TerminalResultPresent -ne $true -or $report.EvidenceExport.TerminalStatus -cne 'Passed')){throw 'Capability terminal evidence differs.'}
    if($Phase -ceq 'Reset'){
      if($report.EvidenceExport.LifecycleAdmitted -ne $false -and $report.EvidenceExport.TerminalResultPresent -ne $true){throw 'An admitted lifecycle has no terminal result; servicing may still be running. Reset is refused.'}
      $report.Stage='ExplicitCheckpointReset';Write-RideCapabilityVmRecord (Join-Path $store ('reset-intent.'+[guid]::NewGuid().ToString('N')+'.json')) $report
      Reset-RideAutomationVm $context.Configuration
      $checked=Import-RideAutomationLab $context.Configuration
      if($checked.VM.State -ne 'Off'){throw 'Capability checkpoint recovery did not leave the VM Off.'}
      $receipt=[pscustomobject]@{SchemaVersion=1;Kind='RetainedGuestRecovery';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;VMId=$owned.Hold.VMId;CheckpointId=$owned.Hold.CheckpointId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;EvidenceExportVerified=$true;CheckpointResetVerified=$true;Status='ResetAndOff';ExportPath=$report.EvidenceExport.Path}
      $receiptPath=Join-Path $store ('recovery.'+[guid]::NewGuid().ToString('N')+'.json');Write-RideCapabilityVmRecord $receiptPath $receipt
      $report.Status='ResetAndOff';$release=$true
    }
    if($Phase -ceq 'Lifecycle'){$report.LifecyclePassed=$true}
    $report.Stage='Retained'
  }catch{
    $report.Status='Failed';$report.Error=$_.Exception.Message
    if($ready -and $report.Stage -cin @('Prepare','Lifecycle')){try{$report.EvidenceExport=Export-RideCapabilityVmEvidence $context.Configuration $credential $descriptor $store}catch{$report.Error+='; Partial export failed: '+$_.Exception.Message}}
  }finally{try{if(Test-Path -LiteralPath $store){Write-RideCapabilityVmRecord (Join-Path $store ('phase.'+[guid]::NewGuid().ToString('N')+'.json')) $report}}finally{$owned.Lock.Dispose()}}
  if($release){
    try{$released=Remove-RideRetainedGuestHold -ConfigurationPath $ConfigurationPath -RunId $RunId -RecoveryReceiptPath $receiptPath -Confirm:$false;if($released.Status -cne 'Released'){throw 'Capability hold release did not complete.'};$report.RecoveryRequired=$false;$report.Stage='Released'}catch{$report.Status='Failed';$report.Stage='HoldRelease';$report.Error=$_.Exception.Message}
    Write-RideCapabilityVmRecord (Join-Path $store ('release.'+[guid]::NewGuid().ToString('N')+'.json')) $report
  }
  $report
}
Register-ArgumentCompleter -CommandName Invoke-RideClientCapabilityVmPhase -ParameterName RunId -ScriptBlock {
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  if($fakeBoundParameters.Phase -eq 'Prepare'){return}
  & $script:retained {param($c,$p,$w,$a,$b) & $script:RetainedRunCompleter $c $p $w $a $b} $commandName $parameterName $wordToComplete $commandAst $fakeBoundParameters
}
Export-ModuleMember -Function Invoke-RideClientCapabilityVmPhase
