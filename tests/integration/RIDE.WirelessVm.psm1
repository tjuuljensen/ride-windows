<#
.SYNOPSIS
  Dispatch explicit synthetic WLAN acceptance phases to a retained disposable VM.
.DESCRIPTION
  Uses the registered lab credential and PowerShell Direct. Stages only seven
  required source/data files with public synthetic settings. A durable
  controller hold survives every phase and failure. Reset requires verified export.
.NOTES
  Native Windows PowerShell 5.1 x64 host with existing elevation. Version: 0.1.0.
  No UAC, task registration, WLAN service start or connection. Remote jobs
  are bounded; host Hyper-V/dependency calls retain their existing API behavior.
.LINK
  ../../docs/wireless-profile-inventory.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.RetainedGuest.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.WirelessAcceptance.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop
$script:WirelessVmSources=@('modules/RIDE.PrivateFiles.psm1','modules/RIDE.WirelessProfile.psm1','modules/RIDE.WirelessLifecycle.psm1','modules/RIDE.WirelessNative.psm1','modules/RIDE.WirelessInventory.psm1','tests/integration/RIDE.WirelessAcceptance.psm1','tests/fixtures/wireless-profile.synthetic.psd1')

function Get-RideWirelessVmHash {
  param([byte[]]$Bytes)
  $sha=[Security.Cryptography.SHA256]::Create()
  try{[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','')}finally{$sha.Dispose()}
}
function New-RideWirelessVmDirectory {
  param([string]$Path)
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $Path
  if(Test-Path -LiteralPath $Path){throw 'Retained directory already exists.'}
  $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  foreach($sid in @('S-1-5-32-544','S-1-5-18')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
  $directory=[IO.DirectoryInfo]::new($Path)
  if($PSVersionTable.PSEdition -eq 'Desktop'){$directory.Create($acl)}else{[IO.FileSystemAclExtensions]::Create($directory,$acl)}
  $actual=Get-Acl -LiteralPath $Path
  if($actual.GetSecurityDescriptorSddlForm('Access,Owner') -cne $acl.GetSecurityDescriptorSddlForm('Access,Owner')){throw 'New retained directory permissions differ.'}
}
function Write-RideWirelessVmRecord {
  param([string]$Path,$Record)
  & (Get-Module RIDE.RetainedGuest) {param($p,$r) Write-RideRetainedRecord $p $r} $Path $Record
}
function Read-RideWirelessVmRecord {
  param([string]$Path)
  & (Get-Module RIDE.RetainedGuest) {param($p) Read-RideRetainedRecord $p} $Path
}
function Get-RideWirelessVmContext {
  param([string]$ConfigurationPath,[bool]$Mutation)
  & (Get-Module RIDE.RetainedGuest) {param($p,$m) Get-RideRetainedConfiguration $p $m} $ConfigurationPath $Mutation
}
function Get-RideWirelessVmCredential {
  param($Configuration)
  & (Get-Module RIDE.TestAutomation) {
    param($config)
    $machine=Get-LabVM -ComputerName $config.VMName
    if(-not $machine.PSObject.Methods['GetCredential']){throw 'Existing lab credential accessor unavailable.'}
    $credential=$machine.GetCredential((Get-Lab))
    if($credential -isnot [pscredential]){throw 'Existing lab did not provide a guest credential.'}
    $credential
  } $Configuration
}
function New-RideWirelessVmSnapshot {
  param([string]$Repository,[string]$Directory)
  New-RideWirelessVmDirectory $Directory
  $files=@();$total=0L
  foreach($relative in $script:WirelessVmSources){
    $source=Join-Path $Repository $relative
    $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $source
    if((Get-Item -LiteralPath $source).Length -gt 16777216){throw 'Snapshot source exceeds its bound.'}
    $bytes=[IO.File]::ReadAllBytes($source);$total+=$bytes.Length
    if($bytes.Length -lt 1 -or $bytes.Length -gt 16777216 -or $total -gt 16777216){throw 'Snapshot exceeds its bound.'}
    $path=Join-Path $Directory $relative;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    $stream=[IO.File]::Open($path,'CreateNew','Write','None')
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $files+=[pscustomobject]@{Path=$relative;Bytes=$bytes.Length;Sha256=(Get-RideWirelessVmHash $bytes)}
  }
  $files
}
function Get-RideWirelessVmPayload {
  param([string]$Directory,$Manifest)
  $expected=@($script:WirelessVmSources)
  if(@($Manifest).Count -ne $expected.Count -or (@($Manifest.Path|Sort-Object) -join ';') -cne (@($expected|Sort-Object) -join ';')){throw 'Snapshot source selection differs.'}
  foreach($entry in $Manifest){
    $path=Join-Path $Directory $entry.Path
    $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.Bytes -or $entry.Bytes -gt 16777216){throw 'Retained snapshot size changed.'}
    $bytes=[IO.File]::ReadAllBytes($path)
    if($bytes.Length -ne $entry.Bytes -or (Get-RideWirelessVmHash $bytes) -cne $entry.Sha256){throw 'Retained snapshot bytes changed.'}
    [pscustomobject]@{Path=$entry.Path;Bytes=$entry.Bytes;Sha256=$entry.Sha256;Content=[Convert]::ToBase64String($bytes)}
  }
}

# This scriptblock is the only remote dispatch target. Neither queue data nor
# caller input supplies PowerShell source, command names, or filesystem roots.
$script:WirelessVmRemote={
  param($Action,$Descriptor,$Payload,[guid]$InterfaceId=[guid]::Empty)
  $ErrorActionPreference='Stop'
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $system=Get-CimInstance Win32_ComputerSystem
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{$elevated=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}finally{$identity.Dispose()}
  if($env:COMPUTERNAME -ine $Descriptor.VMName -or $system.Manufacturer -cne 'Microsoft Corporation' -or $system.Model -cne 'Virtual Machine' -or
    -not $elevated -or -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -cne 'AMD64' -or
    [string]$version.CurrentBuildNumber -cne $Descriptor.ExpectedBuild -or $version.EditionID -cne $Descriptor.ExpectedEditionId -or $version.InstallationType -cne 'Client'){throw 'Retained guest target differs.'}
  $context=[pscustomobject]@{ComputerName=$env:COMPUTERNAME;Build=[string]$version.CurrentBuildNumber;EditionId=$version.EditionID;Revision=[int]$version.UBR}
  if($Action -ceq 'Ready'){return $context}
  if($Descriptor.RunId -cnotmatch '^[a-f0-9]{32}$' -or $Descriptor.LeaseId -cnotmatch '^[a-f0-9]{32}$'){throw 'Invalid retained request identity.'}
  $base='C:\ProgramData\RIDE\RetainedAcceptance\'+$Descriptor.LeaseId
  $expectedSources=@('modules/RIDE.PrivateFiles.psm1','modules/RIDE.WirelessProfile.psm1','modules/RIDE.WirelessLifecycle.psm1','modules/RIDE.WirelessNative.psm1','modules/RIDE.WirelessInventory.psm1','tests/integration/RIDE.WirelessAcceptance.psm1','tests/fixtures/wireless-profile.synthetic.psd1')
  if(@($Descriptor.Manifest).Count -ne $expectedSources.Count -or (@($Descriptor.Manifest.Path|Sort-Object) -join ';') -cne (@($expectedSources|Sort-Object) -join ';')){throw 'Guest source manifest differs from the fixed selection.'}
  function Get-Hash([byte[]]$bytes){$sha=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')}finally{$sha.Dispose()}}
  function Assert-Directory([string]$path){
    $node=[IO.DirectoryInfo]::new($path)
    for($ancestor=$node;$null -ne $ancestor;$ancestor=$ancestor.Parent){if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Guest path contains a reparse point.'}}
    $acl=Get-Acl -LiteralPath $path
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Guest directory owner differs.'}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership') -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Guest directory permits another writer.'}}
  }
  function New-Directory([string]$path){
    if(Test-Path -LiteralPath $path){throw 'Guest directory already exists.'}
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach($sid in @('S-1-5-32-544','S-1-5-18')){
      $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    [IO.DirectoryInfo]::new($path).Create($acl);Assert-Directory $path
  }
  if($Action -ceq 'Prepare'){
    foreach($parent in @('C:\ProgramData\RIDE','C:\ProgramData\RIDE\RetainedAcceptance')){if(Test-Path -LiteralPath $parent){Assert-Directory $parent}else{New-Directory $parent}}
    New-Directory $base
    foreach($child in @('source','evidence')){New-Directory (Join-Path $base $child)}
    foreach($entry in $Descriptor.Manifest){
      $supplied=@($Payload|Where-Object Path -CEQ $entry.Path)
      if($supplied.Count -ne 1 -or $entry.Bytes -lt 1 -or $entry.Bytes -gt 16777216 -or $supplied[0].Content.Length -gt 22369624){throw 'Guest payload selection or bound differs.'}
      $bytes=[Convert]::FromBase64String($supplied[0].Content)
      if($bytes.Length -ne $entry.Bytes -or (Get-Hash $bytes) -cne $entry.Sha256){throw 'Guest payload digest differs.'}
      $destination=Join-Path (Join-Path $base 'source') $entry.Path
      $null=New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
      $stream=[IO.File]::Open($destination,'CreateNew','Write','None');try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    }
  }
  if($Action -ceq 'Collect'){
    if(-not (Test-Path -LiteralPath $base)){return [pscustomobject]@{SchemaVersion=1;Kind='WirelessVmCollection';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Absent';Context=$context;Files=@()}}
    Assert-Directory $base
    $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($base);$files=[Collections.Generic.List[object]]::new();$nodes=0;$total=0L
    while($pending.Count){foreach($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force){
      $nodes++;if($nodes -gt 512 -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Guest evidence traversal limit or reparse conflict.'}
      if($item.PSIsContainer){$pending.Enqueue($item.FullName);continue}
      if($item.Length -gt 16777216){throw 'Guest evidence file exceeds its bound.'}
      $bytes=[IO.File]::ReadAllBytes($item.FullName);$total+=$bytes.Length
      if($total -gt 33554432){throw 'Guest evidence exceeds 32 MiB.'}
      $files.Add([pscustomobject]@{Path=$item.FullName.Substring($base.Length+1).Replace('\','/');Bytes=$bytes.Length;Sha256=(Get-Hash $bytes);Content=[Convert]::ToBase64String($bytes)})
    }}
    return [pscustomobject]@{SchemaVersion=1;Kind='WirelessVmCollection';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Collected';Context=$context;Files=$files.ToArray()}
  }
  Assert-Directory $base
  foreach($entry in $Descriptor.Manifest){
    $path=Join-Path (Join-Path $base 'source') $entry.Path
    $file=Get-Item -LiteralPath $path -Force
    if($file.PSIsContainer -or $file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.Length -ne $entry.Bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.Sha256){throw 'Staged guest source changed.'}
  }
  Import-Module (Join-Path $base 'source/tests/integration/RIDE.WirelessAcceptance.psm1') -Force
  Import-Module (Join-Path $base 'source/modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop
  $env:RIDE_INTEGRATION_VM='1';$env:RIDE_TEST_GUEST='1';$env:RIDE_TEST_RUN_ID=$Descriptor.RunId
  $metadata=Join-Path $base 'prepared.json'
  if($Action -ceq 'Prepare'){
    $availability=& (Get-Module RIDE.WirelessAcceptance) {Get-RideWirelessAcceptanceInterfaces}
    $prepared=[pscustomobject]@{SchemaVersion=1;Kind='WirelessVmPreparation';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status=if($availability.Status -ceq 'Available'){'Prepared'}else{'NotRun'};Context=$context;Availability=$availability;NativeAcceptancePassed=$false}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($prepared|ConvertTo-Json -Depth 8))
    $stream=New-RidePrivateFileStream -Path $metadata -Scope Machine
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    return $prepared
  }
  $bytes=Read-RidePrivateFileBytes -Path $metadata -Scope Machine -MaximumBytes 1048576
  $prepared=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
  if($prepared.RunId -cne $Descriptor.RunId -or $prepared.LeaseId -cne $Descriptor.LeaseId -or $prepared.Context.Revision -ne $context.Revision){throw 'Prepared guest identity/build revision changed.'}
  if($Action -cne 'Lifecycle'){throw 'Unknown fixed guest phase.'}
  if($InterfaceId -eq [guid]::Empty -or $prepared.Availability.Status -cne 'Available' -or @($prepared.Availability.Interfaces|Where-Object Id -CEQ $InterfaceId.ToString('D')).Count -ne 1){throw 'Select a WLAN interface from this prepared guest observation.'}
  Invoke-RideWirelessAcceptance -RunId $Descriptor.RunId -InterfaceId $InterfaceId -ExpectedComputerName $context.ComputerName -ExpectedBuild $Descriptor.ExpectedBuild -ExpectedEditionId $Descriptor.ExpectedEditionId -EvidenceRoot (Join-Path $base 'evidence') -DisposableVm -Confirm:$false
}

function Invoke-RideWirelessVmRemote {
  param($Configuration,[pscredential]$Credential,[string]$Action,$Descriptor,$Payload,[int]$TimeoutSeconds=180,[guid]$InterfaceId=[guid]::Empty)
  $job=Invoke-Command -VMId ([guid]$Configuration.VMId) -Credential $Credential -ScriptBlock $script:WirelessVmRemote -ArgumentList $Action,$Descriptor,$Payload,$InterfaceId.ToString('D') -AsJob -ErrorAction Stop
  try{
    if(-not (Wait-Job $job -Timeout $TimeoutSeconds)){throw 'Remote phase timed out; retain the guest and hold for inspection.'}
    $result=@(Receive-Job $job -ErrorAction Stop)
    if($job.State -ne 'Completed' -or $result.Count -ne 1){throw 'Remote phase did not return one completed result.'}
    $result[0]
  }finally{Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}
}
function Wait-RideWirelessVmReady {
  param($Configuration,[pscredential]$Credential,$Descriptor)
  $deadline=[datetime]::UtcNow.AddMinutes(3)
  do{
    try{return Invoke-RideWirelessVmRemote $Configuration $Credential Ready $Descriptor $null 15}catch{if([datetime]::UtcNow -ge $deadline){throw 'Guest readiness/target verification did not complete within three minutes.'};Start-Sleep -Seconds 2}
  }while($true)
}
function Export-RideWirelessVmEvidence {
  param($Configuration,[pscredential]$Credential,$Descriptor,[string]$Store)
  $collected=Invoke-RideWirelessVmRemote $Configuration $Credential Collect $Descriptor $null
  if($collected.SchemaVersion -ne 1 -or $collected.Kind -cne 'WirelessVmCollection' -or $collected.RunId -cne $Descriptor.RunId -or $collected.LeaseId -cne $Descriptor.LeaseId -or
    $collected.Status -cnotin @('Collected','Absent') -or $collected.Context.ComputerName -ine $Descriptor.VMName -or $collected.Context.Build -cne $Descriptor.ExpectedBuild -or $collected.Context.EditionId -cne $Descriptor.ExpectedEditionId){throw 'Unexpected or mismatched guest collection result.'}
  $export=Join-Path $Store ('export.'+[guid]::NewGuid().ToString('N'));New-RideWirelessVmDirectory $export
  $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L;$manifest=@()
  if(@($collected.Files).Count -gt 512){throw 'Export file count exceeds its bound.'}
  foreach($entry in $collected.Files){
    if($entry.Path -notmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -or @($entry.Path -split '/'|Where-Object {$_ -in @('.','..')}).Count -or -not $names.Add($entry.Path)){throw 'Unsafe or duplicate guest evidence path.'}
    if($entry.Bytes -lt 0 -or $entry.Bytes -gt 16777216 -or $entry.Content.Length -gt 22369624){throw 'Guest evidence encoding exceeds its bound.'}
    $bytes=[Convert]::FromBase64String($entry.Content);$total+=$bytes.Length
    if($bytes.Length -gt 16777216 -or $total -gt 33554432 -or $bytes.Length -ne $entry.Bytes -or (Get-RideWirelessVmHash $bytes) -cne $entry.Sha256){throw 'Guest evidence bytes differ or exceed their bound.'}
    $destination=Join-Path $export $entry.Path;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
    $stream=[IO.File]::Open($destination,'CreateNew','Write','None');try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if((Get-FileHash -LiteralPath $destination).Hash -cne $entry.Sha256){throw 'Exported evidence digest differs.'}
    $manifest+=@([pscustomobject]@{Path=$entry.Path;Bytes=$entry.Bytes;Sha256=$entry.Sha256})
  }
  if($collected.Status -ceq 'Absent' -and $manifest.Count){throw 'Absent guest export contains files.'}
  $receipt=[pscustomobject]@{SchemaVersion=1;Kind='RetainedGuestExport';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status=$collected.Status;Files=$manifest;Context=$collected.Context;RecordedAtUtc=[datetime]::UtcNow.ToString('o')}
  Write-RideWirelessVmRecord (Join-Path $export 'export-receipt.json') $receipt
  [pscustomobject]@{Verified=$true;Path=$export;FileCount=$manifest.Count;GuestStatus=$collected.Status}
}
function Read-RideWirelessVmResetExport {
  param([string]$Store,$Descriptor)
  $intents=@(Get-ChildItem -LiteralPath $Store -Filter 'reset-intent.*.json' -File|Select-Object -First 513)
  if(-not $intents.Count -or $intents.Count -gt 512){throw 'An Off guest requires a retained pre-reset export intent.'}
  $intent=Read-RideWirelessVmRecord ($intents|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1).FullName
  if($intent.SchemaVersion -ne 1 -or $intent.Kind -cne 'WirelessVmResetIntent' -or $intent.RunId -cne $Descriptor.RunId -or $intent.LeaseId -cne $Descriptor.LeaseId -or $intent.ConfigurationSha256 -cne $Descriptor.ConfigurationSha256){throw 'Saved reset/export intent differs.'}
  $leaf=Split-Path -Leaf $intent.ExportPath
  if($leaf -cnotmatch '^export\.[a-f0-9]{32}$' -or $intent.ExportPath -cne (Join-Path $Store $leaf)){throw 'Saved export path escaped its retained store.'}
  $receipt=Read-RideWirelessVmRecord (Join-Path $intent.ExportPath 'export-receipt.json')
  if($receipt.SchemaVersion -ne 1 -or $receipt.Kind -cne 'RetainedGuestExport' -or $receipt.RunId -cne $Descriptor.RunId -or $receipt.LeaseId -cne $Descriptor.LeaseId -or $receipt.Status -cnotin @('Collected','Absent') -or @($receipt.Files).Count -gt 512){throw 'Saved export receipt differs.'}
  if($receipt.Context.ComputerName -ine $Descriptor.VMName -or $receipt.Context.Build -cne $Descriptor.ExpectedBuild -or $receipt.Context.EditionId -cne $Descriptor.ExpectedEditionId -or ($receipt.Status -ceq 'Absent' -and @($receipt.Files).Count)){throw 'Saved export target or absent-state metadata differs.'}
  $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L
  foreach($entry in $receipt.Files){
    if($entry.Path -notmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -or @($entry.Path -split '/'|Where-Object {$_ -in @('.','..')}).Count -or -not $names.Add($entry.Path)){throw 'Unsafe or duplicate saved export path.'}
    $total+=$entry.Bytes
    if($entry.Bytes -lt 0 -or $entry.Bytes -gt 16777216 -or $total -gt 33554432){throw 'Saved export size exceeds its bound.'}
    $path=Join-Path $intent.ExportPath $entry.Path
    $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.Bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.Sha256){throw 'Saved exported evidence changed.'}
  }
  [pscustomobject]@{Verified=$true;Path=$intent.ExportPath;FileCount=@($receipt.Files).Count;GuestStatus=$receipt.Status}
}
function Assert-RideWirelessVmAvailability {
  param($Availability)
  if($Availability.SchemaVersion -ne 1 -or $Availability.Kind -cne 'WirelessInterfaceObservation' -or $Availability.Status -cnotin @('Available','NotRun') -or
    $Availability.NativeAcceptancePassed -ne $false -or $Availability.ConnectionAttempted -ne $false -or $Availability.ProfileContentRead -ne $false -or
    $null -eq $Availability.Interfaces -or $Availability.Interfaces -is [string] -or @($Availability.Interfaces).Count -gt 64){throw 'WLAN availability schema or acceptance boundary differs.'}
  if($Availability.Status -ceq 'NotRun'){
    if($Availability.Reason -cnotin @('WlanServiceUnavailable','WlanInterfaceUnavailable','NoWlanInterfaces') -or @($Availability.Interfaces).Count){throw 'Invalid unavailable WLAN observation.'}
    return
  }
  if($Availability.Reason -or -not @($Availability.Interfaces).Count){throw 'Available WLAN observation needs interface identities.'}
  $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($row in $Availability.Interfaces){
    $id=[guid]::Empty
    if(-not [guid]::TryParse([string]$row.Id,[ref]$id) -or $id -eq [guid]::Empty -or $row.Id -cne $id.ToString('D') -or -not $seen.Add($row.Id) -or
      ($row.State -isnot [uint32] -and $row.State -isnot [int] -and $row.State -isnot [long]) -or $row.State -lt 0 -or $row.State -gt [uint32]::MaxValue -or
      @($row.PSObject.Properties.Name|Where-Object {$_ -cnotin @('Id','State')}).Count){throw 'Invalid or nonminimal WLAN interface observation.'}
  }
}
function Assert-RideWirelessVmGuestResult {
  param($Guest,[string]$Phase,$Descriptor,[guid]$InterfaceId=[guid]::Empty)
  if($Guest.SchemaVersion -ne 1 -or $Guest.RunId -cne $Descriptor.RunId -or $Guest.NativeAcceptancePassed -isnot [bool]){throw 'Guest phase correlation or acceptance boundary differs.'}
  if($Phase -ceq 'Prepare'){
    Assert-RideWirelessVmAvailability $Guest.Availability
    $status=if($Guest.Availability.Status -ceq 'Available'){'Prepared'}else{'NotRun'}
    if($Guest.Kind -cne 'WirelessVmPreparation' -or $Guest.Status -cne $status -or $Guest.LeaseId -cne $Descriptor.LeaseId -or $Guest.NativeAcceptancePassed -or
      $Guest.Context.ComputerName -ine $Descriptor.VMName -or $Guest.Context.Build -cne $Descriptor.ExpectedBuild -or $Guest.Context.EditionId -cne $Descriptor.ExpectedEditionId){throw 'Guest preparation result differs.'}
    return
  }
  if($Guest.Kind -cne 'WirelessLifecycleAcceptance' -or $Guest.ComputerName -ine $Descriptor.VMName -or $Guest.Build -cne $Descriptor.ExpectedBuild -or $Guest.EditionId -cne $Descriptor.ExpectedEditionId -or $Guest.InterfaceId -cne $InterfaceId.ToString('D') -or $Guest.ConnectionAttempted -ne $false){throw 'Guest WLAN target, interface or acceptance boundary differs.'}
  if($Guest.Status -ceq 'NotRun'){
    if($Guest.Reason -cnotin @('ExistingElevationRequired','WlanServiceUnavailable','WlanInterfaceUnavailable','SyntheticProfileCollision') -or $Guest.NativeAcceptancePassed -or $Guest.RecoveryRequired -or @($Guest.Checks).Count -or @($Guest.LifecycleRuns).Count -or @($Guest.StateRunIds).Count){throw 'Invalid unrun WLAN result.'}
    return
  }
  $checks='PreviewNoChanges;ImportAndNativeReadback;RepeatWithoutNewRun;ReplacementAndNativeReadback;PriorSyntheticProfileRestored;OwnedRemoval;RemovedProfileRestored;InitialAbsenceAndOrderRestored;RepeatedRestoreNoChange'
  if($Guest.Status -cne 'Passed' -or $Guest.Stage -cne 'Complete' -or -not $Guest.NativeAcceptancePassed -or $Guest.RecoveryRequired -or ($Guest.Checks -join ';') -cne $checks){throw 'Guest phase did not establish every required lifecycle check.'}
  if(@($Guest.LifecycleRuns).Count -ne 3 -or ($Guest.LifecycleRuns.Action -join ';') -cne 'Import;Replace;Remove' -or
    @($Guest.LifecycleRuns|Where-Object {$_.Restored -ne $true -or $_.RunId -cnotmatch '^[a-f0-9]{32}$'}).Count -or
    @($Guest.LifecycleRuns.RunId|Select-Object -Unique).Count -ne 3 -or
    (@($Guest.StateRunIds|Sort-Object) -join ';') -cne (@($Guest.LifecycleRuns.RunId|Sort-Object) -join ';')){throw 'Guest WLAN recovery runs are incomplete.'}
}

function Invoke-RideWirelessVmPhase {
  <#
  .SYNOPSIS
    Prepare, run synthetic WLAN lifecycle, collect or reset the retained VM.
  .PARAMETER Phase
    Prepare reserves/stages/starts the clean VM; Lifecycle performs all nine
    synthetic profile checks and three captured restores in one guest invocation.
    Collect exports evidence. Reset exports before
    restoring the pinned checkpoint and releasing the hold; it does not pass tests.
  .PARAMETER ConfigurationPath
    Installed controller configuration for the owning elevated host account.
  .PARAMETER RunId
    New request ID for Prepare; reuse for later phases. Completion reads the hold.
  .PARAMETER InterfaceId
    Lifecycle-only WLAN interface GUID from this request's Prepare observation.
  .PARAMETER ExpectedBuild
    Prepare-only exact Windows 11 guest build, at least 22000.
  .PARAMETER ExpectedEditionId
    Prepare-only exact Enterprise/Education guest edition.
  .EXAMPLE
    Invoke-RideWirelessVmPhase -Phase Prepare -ConfigurationPath '<installed-configuration>' -RunId '<request-id>' -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -WhatIf
  .OUTPUTS
    Schema-1 phase report; ProfileLifecycleAcceptancePassed requires all nine checks and verified export.
    NativeAcceptancePassed, ConnectionVerified and FullDaclRecoveryVerified stay false.
    Failures retain the guest, hold and private records; no automatic cleanup runs.
  .NOTES
    Use the registered checkout in an already elevated Windows PowerShell 5.1
    process. Direct invocation only; do not submit through the generic queue.
    Missing WLAN prerequisites return NotRun. Real network credentials are not used.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidateSet('Prepare','Lifecycle','Collect','Reset')][string]$Phase,
    [Parameter(Mandatory)][string]$ConfigurationPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId,
    [guid]$InterfaceId=[guid]::Empty,[ValidatePattern('^\d{5,8}$')][string]$ExpectedBuild,
    [ValidateSet('Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')][string]$ExpectedEditionId)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'RunId must use 32 lowercase hexadecimal characters.'}
  foreach($name in @('Phase','ExpectedEditionId')){
    if($PSBoundParameters.ContainsKey($name)){
      $validation=@($MyInvocation.MyCommand.Parameters[$name].Attributes|Where-Object {$_ -is [Management.Automation.ValidateSetAttribute]})[0]
      $selectedValue=$PSBoundParameters[$name]
      $canonical=@($validation.ValidValues|Where-Object {$_ -ieq $selectedValue})[0]
      if($name -eq 'Phase'){$Phase=$canonical}else{$ExpectedEditionId=$canonical}
    }
  }
  if($Phase -ceq 'Prepare'){
    if(-not $ExpectedEditionId -or -not $ExpectedBuild -or [int]$ExpectedBuild -lt 22000){throw 'Prepare requires the exact Windows 11 build and edition.'}
  }elseif($ExpectedBuild -or $ExpectedEditionId){throw 'Target selections belong only to Prepare.'}
  if($Phase -ceq 'Lifecycle'){if($InterfaceId -eq [guid]::Empty){throw 'Lifecycle requires an observed nonempty InterfaceId.'}}elseif($PSBoundParameters.ContainsKey('InterfaceId')){throw 'InterfaceId belongs only to Lifecycle.'}
  $context=Get-RideWirelessVmContext $ConfigurationPath (-not $WhatIfPreference)
  $repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\')
  if([IO.Path]::GetFullPath($context.Configuration.LocalRepositoryPath).TrimEnd('\') -ine $repository){throw 'Use the registered checkout for retained dispatch.'}
  if(-not $PSCmdlet.ShouldProcess($context.Configuration.VMName,"Run explicit retained synthetic WLAN $Phase phase")){return [pscustomobject]@{SchemaVersion=1;RunId=$RunId;Phase=$Phase;Status='Preview';NativeAcceptancePassed=$false}}
  if($Phase -ceq 'Prepare'){$null=New-RideRetainedGuestHold -ConfigurationPath $ConfigurationPath -RunId $RunId -Confirm:$false}
  $owned=Open-RideRetainedGuestPhase -ConfigurationPath $ConfigurationPath -RunId $RunId
  $store=Join-Path $context.Root ('retained.'+$owned.Hold.LeaseId)
  $report=[pscustomobject][ordered]@{SchemaVersion=1;RunId=$RunId;LeaseId=$owned.Hold.LeaseId;Phase=$Phase;InterfaceId=if($Phase -ceq 'Lifecycle'){$InterfaceId.ToString('D')}else{$null};Status='Failed';Stage='Preflight';NativeAcceptancePassed=$false;ProfileLifecycleAcceptancePassed=$false;ConnectionAttempted=$false;ConnectionVerified=$false;FullDaclRecoveryVerified=$false;RecoveryRequired=$true;EvidenceExport=$null;GuestResult=$null;Error=$null;Store=$store;RecordedAtUtc=[datetime]::UtcNow.ToString('o')}
  $release=$false;$ready=$false
  try{
    if($context.ConfigurationSha256 -cne $owned.Context.ConfigurationSha256){throw 'Controller configuration changed before phase ownership.'}
    if($Phase -ceq 'Prepare'){
      New-RideWirelessVmDirectory $store
      $manifest=@(New-RideWirelessVmSnapshot $repository (Join-Path $store 'snapshot'))
      $descriptor=[pscustomobject]@{SchemaVersion=1;Kind='WirelessVmSession';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;VMName=$context.Configuration.VMName;VMId=$owned.Hold.VMId;CheckpointId=$owned.Hold.CheckpointId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;Manifest=$manifest}
      Write-RideWirelessVmRecord (Join-Path $store 'session.json') $descriptor
    }else{
      $descriptor=Read-RideWirelessVmRecord (Join-Path $store 'session.json')
      foreach($name in @('RunId','LeaseId','VMId','VMName','CheckpointId','ConfigurationSha256')){if($descriptor.$name -cne $owned.Hold.$name){throw 'Saved VM session identity differs.'}}
      if($descriptor.SchemaVersion -ne 1 -or $descriptor.Kind -cne 'WirelessVmSession'){throw 'Saved VM session schema differs.'}
    }
    if($Phase -ceq 'Lifecycle'){
      $observation=Read-RideWirelessVmRecord (Join-Path $store 'wlan-observation.json')
      Assert-RideWirelessVmGuestResult $observation Prepare $descriptor
      if($observation.Status -cne 'Prepared' -or @($observation.Availability.Interfaces|Where-Object Id -CEQ $InterfaceId.ToString('D')).Count -ne 1){throw 'Select an interface from this prepared guest observation.'}
    }
    $retryReset=($Phase -ceq 'Reset' -and $owned.Target.VM.State -eq 'Off')
    $credential=if(-not $retryReset){Get-RideWirelessVmCredential $context.Configuration}else{$null}
    if($Phase -ceq 'Prepare'){
      $payload=@(Get-RideWirelessVmPayload (Join-Path $store 'snapshot') $descriptor.Manifest)
      if($owned.Target.VM.State -ne 'Off'){throw 'Prepare requires the reserved VM to remain Off.'}
      $report.Stage='InitialCheckpoint';Write-RideWirelessVmRecord (Join-Path $store 'prepare-intent.json') $report
      Restore-VMSnapshot -VMSnapshot $owned.Target.Snapshot -Confirm:$false -ErrorAction Stop
      Start-VM -VM $owned.Target.VM -ErrorAction Stop|Out-Null
    }elseif(-not $retryReset -and $owned.Target.VM.State -ne 'Running'){throw 'Retained phases require the guest to remain running; preserve evidence and inspect its state.'}
    if(-not $retryReset){$report.Stage='GuestReadiness';$null=Wait-RideWirelessVmReady $context.Configuration $credential $descriptor;$ready=$true}
    if($Phase -cin @('Prepare','Lifecycle')){
      if($Phase -cne 'Prepare'){$null=@(Get-RideWirelessVmPayload (Join-Path $store 'snapshot') $descriptor.Manifest);$payload=$null}
      $report.Stage=$Phase
      $guest=Invoke-RideWirelessVmRemote $context.Configuration $credential $Phase $descriptor $payload -InterfaceId $InterfaceId
      $report.GuestResult=$guest
      Assert-RideWirelessVmGuestResult $guest $Phase $descriptor $InterfaceId
      if($Phase -ceq 'Prepare'){Write-RideWirelessVmRecord (Join-Path $store 'wlan-observation.json') $guest}
      $report.Status=$guest.Status
      if($Phase -ceq 'Lifecycle' -and $guest.Status -ceq 'Passed'){$report.ProfileLifecycleAcceptancePassed=$true}
    }else{$report.Status='Collected'}
    $report.Stage='EvidenceExport'
    $report.EvidenceExport=if($retryReset){Read-RideWirelessVmResetExport $store $descriptor}else{Export-RideWirelessVmEvidence $context.Configuration $credential $descriptor $store}
    if($report.EvidenceExport.Verified -ne $true -or ($Phase -cin @('Prepare','Lifecycle') -and ($report.EvidenceExport.GuestStatus -cne 'Collected' -or $report.EvidenceExport.FileCount -lt 1))){throw 'Required guest evidence was not exported.'}
    if($Phase -ceq 'Reset'){
      $report.Stage='ExplicitCheckpointReset'
      Write-RideWirelessVmRecord (Join-Path $store ('reset-intent.'+[guid]::NewGuid().ToString('N')+'.json')) ([pscustomobject]@{SchemaVersion=1;Kind='WirelessVmResetIntent';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;ExportPath=$report.EvidenceExport.Path})
      Reset-RideAutomationVm $context.Configuration
      $checked=Import-RideAutomationLab $context.Configuration
      if($checked.VM.State -ne 'Off'){throw 'Explicit checkpoint recovery did not leave the pinned guest Off.'}
      $receipt=[pscustomobject]@{SchemaVersion=1;Kind='RetainedGuestRecovery';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;VMId=$owned.Hold.VMId;CheckpointId=$owned.Hold.CheckpointId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;EvidenceExportVerified=$true;CheckpointResetVerified=$true;Status='ResetAndOff';ExportPath=$report.EvidenceExport.Path}
      $receiptPath=Join-Path $store ('recovery.'+[guid]::NewGuid().ToString('N')+'.json')
      Write-RideWirelessVmRecord $receiptPath $receipt
      $report.Status='ResetAndOff';$release=$true
    }
    $report.Stage='Retained'
  }catch{
    $report.Status='Failed';$report.ProfileLifecycleAcceptancePassed=$false;$report.Error=$_.Exception.Message
    if($ready -and $report.Stage -cin @('Prepare','Lifecycle')){
      try{$report.EvidenceExport=Export-RideWirelessVmEvidence $context.Configuration $credential $descriptor $store}catch{$report.Error+='; Partial evidence export failed: '+$_.Exception.Message}
    }
  }
  finally{
    try{if(Test-Path -LiteralPath $store -PathType Container){Write-RideWirelessVmRecord (Join-Path $store ('phase.'+[guid]::NewGuid().ToString('N')+'.json')) $report}}finally{$owned.Lock.Dispose()}
  }
  if($release){
    try{$released=Remove-RideRetainedGuestHold -ConfigurationPath $ConfigurationPath -RunId $RunId -RecoveryReceiptPath $receiptPath -Confirm:$false;if($released.Status -cne 'Released'){throw 'Hold release did not complete.'};$report.RecoveryRequired=$false;$report.Stage='Released'}catch{$report.Status='Failed';$report.Stage='HoldRelease';$report.Error=$_.Exception.Message}
    Write-RideWirelessVmRecord (Join-Path $store ('release.'+[guid]::NewGuid().ToString('N')+'.json')) $report
  }
  $report
}
Register-ArgumentCompleter -CommandName Invoke-RideWirelessVmPhase -ParameterName RunId -ScriptBlock {
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  if($fakeBoundParameters.Phase -eq 'Prepare'){return}
  & (Get-Module RIDE.RetainedGuest) {param($c,$p,$w,$a,$b) & $script:RetainedRunCompleter $c $p $w $a $b} $commandName $parameterName $wordToComplete $commandAst $fakeBoundParameters
}
function Get-RideWirelessVmSavedObservation {
  param([string]$ConfigurationPath,[string]$RunId)
  & (Get-Module RIDE.RetainedGuest) {
      param($path,$run)
      $configuration=Read-RideAutomationConfiguration $path;$root=Get-RideAutomationRoot $configuration.Name
      if([IO.Path]::GetFullPath($path) -ine (Join-Path $root 'configuration.json')){return}
      $hold=Read-RideRetainedRecord (Join-Path $root 'runtime/blocked.json')
      if($hold.Kind -cne 'RetainedGuestAcceptance' -or $hold.RunId -cne $run -or $hold.LeaseId -cnotmatch '^[a-f0-9]{32}$'){return}
      $observation=Read-RideRetainedRecord (Join-Path $root ('retained.'+$hold.LeaseId+'/wlan-observation.json'))
      if($observation.RunId -cne $run -or $observation.LeaseId -cne $hold.LeaseId -or $observation.Kind -cne 'WirelessVmPreparation' -or $observation.Status -cne 'Prepared'){return}
      $observation
  } $ConfigurationPath $RunId
}
$script:WirelessVmInterfaceCompleter={
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{
    if($fakeBoundParameters.Phase -ine 'Lifecycle' -or -not $fakeBoundParameters.ConfigurationPath -or $fakeBoundParameters.RunId -cnotmatch '^[a-f0-9]{32}$'){return}
    $saved=Get-RideWirelessVmSavedObservation $fakeBoundParameters.ConfigurationPath $fakeBoundParameters.RunId
    if($null -eq $saved){return}
    Assert-RideWirelessVmAvailability $saved.Availability
    foreach($row in $saved.Availability.Interfaces){if($row.Id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($row.Id,$row.Id,'ParameterValue','Observed disposable guest WLAN interface')}}
  }catch{}
}
Register-ArgumentCompleter -CommandName Invoke-RideWirelessVmPhase -ParameterName InterfaceId -ScriptBlock $script:WirelessVmInterfaceCompleter
Export-ModuleMember -Function Invoke-RideWirelessVmPhase
