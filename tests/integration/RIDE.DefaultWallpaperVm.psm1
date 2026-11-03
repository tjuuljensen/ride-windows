<#
.SYNOPSIS
  Dispatch explicit first-logon wallpaper acceptance phases to a retained disposable VM.
.DESCRIPTION
  Uses the registered lab credential and PowerShell Direct. Stages only six
  required source files and the pinned PNG. A durable controller hold survives
  every phase and failure. Reset is explicit and requires a verified export.
  Explicit user phases create, inspect and remove the owned wallpaper fixtures.
  Synthetic SecureString input is transported separately and never journaled.
  User removal exports available evidence before deleting its owned profile.
.NOTES
  Native Windows PowerShell 5.1 x64 host with existing elevation. Version: 0.1.2.
  Phase reports expose snapshot paths, sizes and hashes without source bytes.
  No UAC, task registration, sign-out or visual acceptance inference. Remote jobs
  are bounded; host Hyper-V/dependency calls retain their existing API behavior.
.LINK
  ../../docs/image-personalization.md
#>
$ErrorActionPreference='Stop'
$script:AutomationModule=Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -PassThru -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.RetainedGuest.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.DefaultWallpaperAcceptance.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop
$script:DefaultWallpaperVmSources=@('modules/RIDE.PrivateFiles.psm1','modules/RIDE.ImageFiles.psm1','modules/RIDE.DefaultWallpaper.psm1','tests/integration/RIDE.DefaultWallpaperAcceptance.psm1','tests/integration/RIDE.WallpaperTestUser.psm1','tests/fixtures/default-wallpaper.acceptance.psd1')

function Get-RideDefaultWallpaperVmHash {
  param([byte[]]$Bytes)
  $sha=[Security.Cryptography.SHA256]::Create()
  try{[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','')}finally{$sha.Dispose()}
}
function New-RideDefaultWallpaperVmDirectory {
  param([string]$Path)
  & (Get-Module RIDE.DefaultWallpaperAcceptance) {param($p) New-RideDefaultWallpaperAcceptanceDirectory $p $false} $Path
}
function Write-RideDefaultWallpaperVmRecord {
  param([string]$Path,$Record)
  & (Get-Module RIDE.RetainedGuest) {param($p,$r) Write-RideRetainedRecord $p $r} $Path $Record
}
function Read-RideDefaultWallpaperVmRecord {
  param([string]$Path)
  & (Get-Module RIDE.RetainedGuest) {param($p) Read-RideRetainedRecord $p} $Path
}
function Get-RideDefaultWallpaperVmContext {
  param([string]$ConfigurationPath,[bool]$Mutation)
  & (Get-Module RIDE.RetainedGuest) {param($p,$m) Get-RideRetainedConfiguration $p $m} $ConfigurationPath $Mutation
}
function Get-RideDefaultWallpaperVmSource {
  param([string]$Path)
  & (Get-Module RIDE.DefaultWallpaperAcceptance) {param($p) Read-RideDefaultWallpaperAcceptanceSource $p} $Path
}
function Get-RideDefaultWallpaperVmCredential {
  param($Configuration)
  & $script:AutomationModule {
    param($config)
    $machine=Get-LabVM -ComputerName $config.VMName
    if(-not $machine.PSObject.Methods['GetCredential']){throw 'Existing lab credential accessor unavailable.'}
    $credential=$machine.GetCredential((Get-Lab))
    if($credential -isnot [pscredential]){throw 'Existing lab did not provide a guest credential.'}
    $credential
  } $Configuration
}
function New-RideDefaultWallpaperVmSnapshot {
  param([string]$Repository,[string]$Directory,$Image)
  New-RideDefaultWallpaperVmDirectory $Directory
  $files=@()
  foreach($relative in @($script:DefaultWallpaperVmSources)+@('inputs/fedora_sharpened_4k.png')){
    $source=if($relative -like 'inputs/*'){$Image.Path}else{Join-Path $Repository $relative}
    $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $source
    if((Get-Item -LiteralPath $source).Length -gt 16777216){throw 'Snapshot source exceeds its bound.'}
    $bytes=[IO.File]::ReadAllBytes($source)
    if($bytes.Length -gt 16777216){throw 'Snapshot member exceeds its bound.'}
    $hash=Get-RideDefaultWallpaperVmHash $bytes
    if($relative -like 'inputs/*' -and ($hash -cne $Image.Sha256 -or $bytes.Length -ne $Image.Bytes)){throw 'Selected image changed during snapshot creation.'}
    $path=Join-Path $Directory $relative
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    $stream=[IO.File]::Open($path,'CreateNew','Write','None')
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $files+=[pscustomobject]@{Path=$relative;Bytes=$bytes.Length;Sha256=$hash}
  }
  $files
}
function Get-RideDefaultWallpaperVmPayload {
  param([string]$Directory,$Manifest)
  $expected=@($script:DefaultWallpaperVmSources)+@('inputs/fedora_sharpened_4k.png')
  if(@($Manifest).Count -ne $expected.Count -or (@($Manifest.Path|Sort-Object) -join ';') -cne (@($expected|Sort-Object) -join ';')){throw 'Snapshot source selection differs.'}
  foreach($entry in $Manifest){
    $path=Join-Path $Directory $entry.Path
    $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.Bytes -or $entry.Bytes -gt 16777216){throw 'Retained snapshot size changed.'}
    $bytes=[IO.File]::ReadAllBytes($path)
    if($bytes.Length -ne $entry.Bytes -or (Get-RideDefaultWallpaperVmHash $bytes) -cne $entry.Sha256){throw 'Retained snapshot bytes changed.'}
    [pscustomobject]@{Path=$entry.Path;Bytes=$entry.Bytes;Sha256=$entry.Sha256;Content=[Convert]::ToBase64String($bytes)}
  }
}

# This scriptblock is the only remote dispatch target. Neither queue data nor
# caller input supplies PowerShell source, command names, or filesystem roots.
$script:DefaultWallpaperVmRemote={
  param($Action,$Descriptor,$Payload,$Purpose,[securestring]$UserPassword)
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
  $expectedSources=@('modules/RIDE.PrivateFiles.psm1','modules/RIDE.ImageFiles.psm1','modules/RIDE.DefaultWallpaper.psm1','tests/integration/RIDE.DefaultWallpaperAcceptance.psm1','tests/integration/RIDE.WallpaperTestUser.psm1','tests/fixtures/default-wallpaper.acceptance.psd1','inputs/fedora_sharpened_4k.png')
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
    foreach($sid in @('S-1-5-32-544','S-1-5-18','S-1-5-32-545')){
      $rights=if($sid -eq 'S-1-5-32-545'){'ReadAndExecute'}else{'FullControl'}
      $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$rights,'ContainerInherit,ObjectInherit','None','Allow'))
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
    if(-not (Test-Path -LiteralPath $base)){return [pscustomobject]@{SchemaVersion=1;Kind='DefaultWallpaperVmCollection';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Absent';Context=$context;Files=@()}}
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
    return [pscustomobject]@{SchemaVersion=1;Kind='DefaultWallpaperVmCollection';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Collected';Context=$context;Files=$files.ToArray()}
  }
  Assert-Directory $base
  foreach($entry in $Descriptor.Manifest){
    $path=Join-Path (Join-Path $base 'source') $entry.Path
    $file=Get-Item -LiteralPath $path -Force
    if($file.PSIsContainer -or $file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.Length -ne $entry.Bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.Sha256){throw 'Staged guest source changed.'}
  }
  Import-Module (Join-Path $base 'source/tests/integration/RIDE.DefaultWallpaperAcceptance.psm1') -Force
  Import-Module (Join-Path $base 'source/tests/integration/RIDE.WallpaperTestUser.psm1') -Force
  $env:RIDE_INTEGRATION_VM='1';$env:RIDE_TEST_GUEST='1';$env:RIDE_TEST_RUN_ID=$Descriptor.RunId
  $fixtureDirectory=Join-Path $base 'users'
  $metadata=Join-Path $base 'prepared.json'
  if($Action -ceq 'Prepare'){
    & (Get-Module RIDE.DefaultWallpaperAcceptance) {param($p) New-RideDefaultWallpaperAcceptanceDirectory $p $false} $fixtureDirectory
    & (Get-Module RIDE.DefaultWallpaperAcceptance) {param($p,$r) Save-RideDefaultWallpaperAcceptanceRecord $p $r} $metadata ([pscustomobject]@{RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Context=$context})
    return [pscustomobject]@{SchemaVersion=1;Kind='DefaultWallpaperVmPreparation';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Prepared';Context=$context;NativeAcceptancePassed=$false}
  }
  $prepared=& (Get-Module RIDE.DefaultWallpaperAcceptance) {param($p) Read-RideDefaultWallpaperAcceptanceRecord $p} $metadata
  if($prepared.RunId -cne $Descriptor.RunId -or $prepared.LeaseId -cne $Descriptor.LeaseId -or $prepared.Context.Revision -ne $context.Revision){throw 'Prepared guest identity/build revision changed.'}
  if($Action -cin @('CreateUser','InspectUser','RemoveUser')){
    if($Purpose -cnotin @('Control','FirstLogon','Recovery')){throw 'Unknown wallpaper fixture purpose.'}
    $fixture=@{RunId=$Descriptor.RunId;Purpose=$Purpose;StateDirectory=$fixtureDirectory;DisposableVm=$true}
    if($Action -ceq 'CreateUser'){
      if($null -eq $UserPassword -or $UserPassword.Length -lt 16 -or $UserPassword.Length -gt 128){throw 'CreateUser requires a synthetic SecureString of 16-128 characters.'}
      $result=New-RideWallpaperTestUser @fixture -Password $UserPassword -ExpectedComputerName $context.ComputerName -ExpectedBuild $Descriptor.ExpectedBuild -ExpectedEditionId $Descriptor.ExpectedEditionId -Confirm:$false
    }elseif($Action -ceq 'InspectUser'){$result=Get-RideWallpaperTestUser @fixture}
    else{$result=Remove-RideWallpaperTestUser @fixture -Confirm:$false}
    return [pscustomobject]@{SchemaVersion=1;Kind='DefaultWallpaperVmUserPhase';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Phase=$Action;Purpose=$Purpose;Status=$result.Status;Context=$context;FixtureResult=$result;NativeAcceptancePassed=$false}
  }
  if($Action -cnotin @('Apply','Restore')){throw 'Unknown fixed guest phase.'}
  $parameters=@{Phase=$Action;RunId=$Descriptor.RunId;ExpectedComputerName=$context.ComputerName;ExpectedBuild=$Descriptor.ExpectedBuild;ExpectedEditionId=$Descriptor.ExpectedEditionId;EvidenceRoot=(Join-Path $base 'evidence');DisposableVm=$true;Confirm=$false}
  if($Action -ceq 'Apply'){$parameters.SourcePath=Join-Path $base 'source/inputs/fedora_sharpened_4k.png'}
  Invoke-RideDefaultWallpaperAcceptance @parameters
}

function Invoke-RideDefaultWallpaperVmRemote {
  param($Configuration,[pscredential]$Credential,[string]$Action,$Descriptor,$Payload,[int]$TimeoutSeconds=180,[string]$Purpose,[securestring]$UserPassword)
  $job=Invoke-Command -VMId ([guid]$Configuration.VMId) -Credential $Credential -ScriptBlock $script:DefaultWallpaperVmRemote -ArgumentList $Action,$Descriptor,$Payload,$Purpose,$UserPassword -AsJob -ErrorAction Stop
  try{
    if(-not (Wait-Job $job -Timeout $TimeoutSeconds)){throw 'Remote phase timed out; retain the guest and hold for inspection.'}
    $result=@(Receive-Job $job -ErrorAction Stop)
    if($job.State -ne 'Completed' -or $result.Count -ne 1){throw 'Remote phase did not return one completed result.'}
    $result[0]
  }finally{Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}
}
function Wait-RideDefaultWallpaperVmReady {
  param($Configuration,[pscredential]$Credential,$Descriptor)
  $deadline=[datetime]::UtcNow.AddMinutes(3)
  do{
    try{return Invoke-RideDefaultWallpaperVmRemote $Configuration $Credential Ready $Descriptor $null 15}catch{if([datetime]::UtcNow -ge $deadline){throw 'Guest readiness/target verification did not complete within three minutes.'};Start-Sleep -Seconds 2}
  }while($true)
}
function Export-RideDefaultWallpaperVmEvidence {
  param($Configuration,[pscredential]$Credential,$Descriptor,[string]$Store)
  $collected=Invoke-RideDefaultWallpaperVmRemote $Configuration $Credential Collect $Descriptor $null
  if($collected.SchemaVersion -ne 1 -or $collected.Kind -cne 'DefaultWallpaperVmCollection' -or $collected.RunId -cne $Descriptor.RunId -or $collected.LeaseId -cne $Descriptor.LeaseId -or
    $collected.Status -cnotin @('Collected','Absent') -or $collected.Context.ComputerName -ine $Descriptor.VMName -or $collected.Context.Build -cne $Descriptor.ExpectedBuild -or $collected.Context.EditionId -cne $Descriptor.ExpectedEditionId){throw 'Unexpected or mismatched guest collection result.'}
  $export=Join-Path $Store ('export.'+[guid]::NewGuid().ToString('N'));New-RideDefaultWallpaperVmDirectory $export
  $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L;$manifest=@()
  if(@($collected.Files).Count -gt 512){throw 'Export file count exceeds its bound.'}
  foreach($entry in $collected.Files){
    if($entry.Path -notmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -or @($entry.Path -split '/'|Where-Object {$_ -in @('.','..')}).Count -or -not $names.Add($entry.Path)){throw 'Unsafe or duplicate guest evidence path.'}
    if($entry.Bytes -lt 0 -or $entry.Bytes -gt 16777216 -or $entry.Content.Length -gt 22369624){throw 'Guest evidence encoding exceeds its bound.'}
    $bytes=[Convert]::FromBase64String($entry.Content);$total+=$bytes.Length
    if($bytes.Length -gt 16777216 -or $total -gt 33554432 -or $bytes.Length -ne $entry.Bytes -or (Get-RideDefaultWallpaperVmHash $bytes) -cne $entry.Sha256){throw 'Guest evidence bytes differ or exceed their bound.'}
    $destination=Join-Path $export $entry.Path;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
    $stream=[IO.File]::Open($destination,'CreateNew','Write','None');try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if((Get-FileHash -LiteralPath $destination).Hash -cne $entry.Sha256){throw 'Exported evidence digest differs.'}
    $manifest+=@([pscustomobject]@{Path=$entry.Path;Bytes=$entry.Bytes;Sha256=$entry.Sha256})
  }
  if($collected.Status -ceq 'Absent' -and $manifest.Count){throw 'Absent guest export contains files.'}
  $receipt=[pscustomobject]@{SchemaVersion=1;Kind='RetainedGuestExport';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status=$collected.Status;Files=$manifest;Context=$collected.Context;RecordedAtUtc=[datetime]::UtcNow.ToString('o')}
  Write-RideDefaultWallpaperVmRecord (Join-Path $export 'export-receipt.json') $receipt
  [pscustomobject]@{Verified=$true;Path=$export;FileCount=$manifest.Count;GuestStatus=$collected.Status}
}
function Read-RideDefaultWallpaperVmResetExport {
  param([string]$Store,$Descriptor)
  $intents=@(Get-ChildItem -LiteralPath $Store -Filter 'reset-intent.*.json' -File|Select-Object -First 513)
  if(-not $intents.Count -or $intents.Count -gt 512){throw 'An Off guest requires a retained pre-reset export intent.'}
  $intent=Read-RideDefaultWallpaperVmRecord ($intents|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1).FullName
  if($intent.SchemaVersion -ne 1 -or $intent.Kind -cne 'DefaultWallpaperVmResetIntent' -or $intent.RunId -cne $Descriptor.RunId -or $intent.LeaseId -cne $Descriptor.LeaseId -or $intent.ConfigurationSha256 -cne $Descriptor.ConfigurationSha256){throw 'Saved reset/export intent differs.'}
  $leaf=Split-Path -Leaf $intent.ExportPath
  if($leaf -cnotmatch '^export\.[a-f0-9]{32}$' -or $intent.ExportPath -cne (Join-Path $Store $leaf)){throw 'Saved export path escaped its retained store.'}
  $receipt=Read-RideDefaultWallpaperVmRecord (Join-Path $intent.ExportPath 'export-receipt.json')
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
function Assert-RideDefaultWallpaperVmGuestResult {
  param($Guest,[string]$Phase,$Descriptor,[string]$Purpose)
  if($Guest.SchemaVersion -ne 1 -or $Guest.RunId -cne $Descriptor.RunId -or $Guest.NativeAcceptancePassed -isnot [bool] -or $Guest.NativeAcceptancePassed){throw 'Guest phase correlation or acceptance boundary differs.'}
  if($Phase -ceq 'Prepare'){
    if($Guest.Kind -cne 'DefaultWallpaperVmPreparation' -or $Guest.Status -cne 'Prepared' -or $Guest.LeaseId -cne $Descriptor.LeaseId){throw 'Guest preparation result differs.'}
  }elseif($Phase -cin @('CreateUser','InspectUser','RemoveUser')){
    $statuses=switch($Phase){CreateUser {@('Created','AlreadyCreated')};InspectUser {@('Observed')};RemoveUser {@('Removed','AlreadyRemoved')}}
    $fixture=$Guest.FixtureResult
    $name='ridewp_'+$Purpose.Substring(0,1).ToLowerInvariant()+'_'+$Descriptor.RunId.Substring(0,10)
    if($Guest.Kind -cne 'DefaultWallpaperVmUserPhase' -or $Guest.Phase -cne $Phase -or $Guest.LeaseId -cne $Descriptor.LeaseId -or $Guest.Purpose -cne $Purpose -or $Guest.Status -cnotin $statuses -or
      $Guest.Context.ComputerName -ine $Descriptor.VMName -or $Guest.Context.Build -cne $Descriptor.ExpectedBuild -or $Guest.Context.EditionId -cne $Descriptor.ExpectedEditionId -or
      $fixture.SchemaVersion -ne 1 -or $fixture.Kind -cne 'WallpaperTestUserResult' -or $fixture.RunId -cne $Descriptor.RunId -or $fixture.Purpose -cne $Purpose -or $fixture.Status -cne $Guest.Status -or
      $fixture.Name -cne $name -or $fixture.Sid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or $fixture.NativeAcceptancePassed -ne $false -or $fixture.NativeFirstLogonAcceptancePassed -ne $false){throw 'Guest user-fixture identity or acceptance boundary differs.'}
    if($null -eq $fixture.State -or $fixture.State.ProfileDirectoryExists -isnot [bool] -or $fixture.State.SessionCount -isnot [int] -or $fixture.State.SessionCount -lt 0 -or
      $fixture.ProfilePath -cnotmatch '^[A-Za-z]:\\' -or [IO.Path]::GetFullPath($fixture.ProfilePath) -cne $fixture.ProfilePath -or [IO.Path]::GetFileName($fixture.ProfilePath) -cne $name){throw 'Guest user-fixture state or profile path is incomplete.'}
    if($Phase -ceq 'RemoveUser' -and ($fixture.State.Account -or $fixture.State.Profile -or $fixture.State.ProfileDirectoryExists)){throw 'Guest fixture removal did not verify.'}
    if($Phase -ceq 'CreateUser' -and ($null -eq $fixture.State.Account -or $fixture.State.Account.Sid -cne $fixture.Sid -or -not $fixture.State.Account.Enabled -or ($fixture.State.Groups -join ';') -cne 'S-1-5-32-545')){throw 'Guest standard-user creation did not verify.'}
  }else{
    $expected=if($Phase -ceq 'Apply'){'AwaitingVisualVerification'}else{'LifecyclePassedVisualPending'}
    $checks=if($Phase -ceq 'Apply'){'PreviewNoChanges;AppliedPolicyThemeImageAndPrivateState;RepeatNoChanges'}else{'RestorePreviewNoChanges;CapturedStateRestored;RepeatedRestoreNoChanges'}
    if($Guest.Kind -cne 'DefaultWallpaperAcceptance' -or $Guest.Phase -cne $Phase -or $Guest.Status -cne $expected -or ($Guest.Checks -join ';') -cne $checks -or $Guest.NativeVisualAcceptancePassed -ne $false -or $Guest.NativeFirstLogonAcceptancePassed -ne $false -or $Guest.NativeLifecycleAcceptancePassed -ne ($Phase -ceq 'Restore')){throw 'Guest phase did not establish every required lifecycle check.'}
  }
}

function Invoke-RideDefaultWallpaperVmPhase {
  <#
  .SYNOPSIS
    Prepare, apply, restore, collect or explicitly reset the retained first-logon wallpaper VM.
  .PARAMETER Phase
    Prepare reserves/stages/starts the clean VM; Apply and Restore keep it running
    for independent visual checks. Collect exports evidence. Reset exports before
    restoring the pinned checkpoint and releasing the hold; it does not pass tests.
  .PARAMETER ConfigurationPath
    Installed controller configuration for the owning elevated host account.
  .PARAMETER RunId
    New request ID for Prepare; reuse for later phases. Completion reads the hold.
  .PARAMETER SourcePath
    Prepare-only pinned first-logon wallpaper PNG. No source input is accepted later.
  .PARAMETER ExpectedBuild
    Prepare-only exact Windows 11 guest build, at least 22000.
  .PARAMETER ExpectedEditionId
    Prepare-only exact Enterprise/Education guest edition.
  .PARAMETER Purpose
    Required only for CreateUser, InspectUser and RemoveUser: Control, FirstLogon
    or Recovery. Keep Control through machine restoration; remove FirstLogon first.
  .PARAMETER UserPassword
    Synthetic SecureString required only for actual CreateUser, 16-128 characters.
    Sent separately through PowerShell Direct, never stored in manifests or reports.
  .EXAMPLE
    Invoke-RideDefaultWallpaperVmPhase -Phase Prepare -ConfigurationPath '<installed-configuration>' -RunId '<request-id>' -SourcePath '<selected-image>' -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -WhatIf
  .OUTPUTS
    Schema-1 phase report. NativeAcceptancePassed stays false. Failures retain
    the guest, hold and private records; no automatic checkpoint cleanup runs.
  .NOTES
    Use the registered checkout in an already elevated Windows PowerShell 5.1
    process. Direct invocation only; do not submit through the generic queue.
    Verify initial/applied/recovered images separately before explicit Reset.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidateSet('Prepare','CreateUser','InspectUser','RemoveUser','Apply','Restore','Collect','Reset')][string]$Phase,
    [Parameter(Mandatory)][string]$ConfigurationPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId,
    [string]$SourcePath,[ValidatePattern('^\d{5,8}$')][string]$ExpectedBuild,
    [ValidateSet('Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')][string]$ExpectedEditionId,
    [ValidateSet('Control','FirstLogon','Recovery')][string]$Purpose,[securestring]$UserPassword)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'RunId must use 32 lowercase hexadecimal characters.'}
  foreach($name in @('Phase','ExpectedEditionId','Purpose')){
    if($PSBoundParameters.ContainsKey($name)){
      $validation=@($MyInvocation.MyCommand.Parameters[$name].Attributes|Where-Object {$_ -is [Management.Automation.ValidateSetAttribute]})[0]
      $selectedValue=$PSBoundParameters[$name]
      $canonical=@($validation.ValidValues|Where-Object {$_ -ieq $selectedValue})[0]
      if($name -eq 'Phase'){$Phase=$canonical}elseif($name -eq 'Purpose'){$Purpose=$canonical}else{$ExpectedEditionId=$canonical}
    }
  }
  if($Phase -ceq 'Prepare'){
    if(-not $SourcePath -or -not $ExpectedEditionId -or -not $ExpectedBuild -or [int]$ExpectedBuild -lt 22000){throw 'Prepare requires the selected source, exact Windows 11 build and edition.'}
  }elseif($SourcePath -or $ExpectedBuild -or $ExpectedEditionId){throw 'Source and target selections belong only to Prepare.'}
  $userPhase=$Phase -cin @('CreateUser','InspectUser','RemoveUser')
  if(($userPhase -and -not $Purpose) -or (-not $userPhase -and $PSBoundParameters.ContainsKey('Purpose'))){throw 'Purpose is required only for user-fixture phases.'}
  if($Phase -cne 'CreateUser' -and $PSBoundParameters.ContainsKey('UserPassword')){throw 'UserPassword belongs only to CreateUser.'}
  if($Phase -ceq 'CreateUser' -and -not $WhatIfPreference -and ($null -eq $UserPassword -or $UserPassword.Length -lt 16 -or $UserPassword.Length -gt 128)){throw 'CreateUser requires a synthetic SecureString of 16-128 characters.'}
  $context=Get-RideDefaultWallpaperVmContext $ConfigurationPath (-not $WhatIfPreference)
  $repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\')
  if([IO.Path]::GetFullPath($context.Configuration.LocalRepositoryPath).TrimEnd('\') -ine $repository){throw 'Use the registered checkout for retained dispatch.'}
  $image=if($Phase -ceq 'Prepare'){Get-RideDefaultWallpaperVmSource $SourcePath}else{$null}
  if(-not $PSCmdlet.ShouldProcess($context.Configuration.VMName,"Run explicit retained first-logon wallpaper $Phase phase")){return [pscustomobject]@{SchemaVersion=1;RunId=$RunId;Phase=$Phase;Status='Preview';NativeAcceptancePassed=$false}}
  if($Phase -ceq 'Prepare'){$null=New-RideRetainedGuestHold -ConfigurationPath $ConfigurationPath -RunId $RunId -Confirm:$false}
  $owned=Open-RideRetainedGuestPhase -ConfigurationPath $ConfigurationPath -RunId $RunId
  $store=Join-Path $context.Root ('retained.'+$owned.Hold.LeaseId)
  $report=[pscustomobject][ordered]@{SchemaVersion=1;RunId=$RunId;LeaseId=$owned.Hold.LeaseId;Phase=$Phase;Purpose=$Purpose;Status='Failed';Stage='Preflight';NativeAcceptancePassed=$false;RecoveryRequired=$true;PreCleanupExport=$null;EvidenceExport=$null;GuestResult=$null;Error=$null;Store=$store;RecordedAtUtc=[datetime]::UtcNow.ToString('o')}
  $release=$false;$ready=$false
  try{
    if($context.ConfigurationSha256 -cne $owned.Context.ConfigurationSha256){throw 'Controller configuration changed before phase ownership.'}
    if($Phase -ceq 'Prepare'){
      New-RideDefaultWallpaperVmDirectory $store
      $manifest=@(New-RideDefaultWallpaperVmSnapshot $repository (Join-Path $store 'snapshot') $image)
      $descriptor=[pscustomobject]@{SchemaVersion=1;Kind='DefaultWallpaperVmSession';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;VMName=$context.Configuration.VMName;VMId=$owned.Hold.VMId;CheckpointId=$owned.Hold.CheckpointId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;Manifest=$manifest}
      Write-RideDefaultWallpaperVmRecord (Join-Path $store 'session.json') $descriptor
    }else{
      $descriptor=Read-RideDefaultWallpaperVmRecord (Join-Path $store 'session.json')
      foreach($name in @('RunId','LeaseId','VMId','VMName','CheckpointId','ConfigurationSha256')){if($descriptor.$name -cne $owned.Hold.$name){throw 'Saved VM session identity differs.'}}
      if($descriptor.SchemaVersion -ne 1 -or $descriptor.Kind -cne 'DefaultWallpaperVmSession'){throw 'Saved VM session schema differs.'}
    }
    $report|Add-Member -NotePropertyName SourceManifest -NotePropertyValue @($descriptor.Manifest|Select-Object Path,Bytes,Sha256)
    $retryReset=($Phase -ceq 'Reset' -and $owned.Target.VM.State -eq 'Off')
    $credential=if(-not $retryReset){Get-RideDefaultWallpaperVmCredential $context.Configuration}else{$null}
    if($Phase -ceq 'Prepare'){
      $payload=@(Get-RideDefaultWallpaperVmPayload (Join-Path $store 'snapshot') $descriptor.Manifest)
      if($owned.Target.VM.State -ne 'Off'){throw 'Prepare requires the reserved VM to remain Off.'}
      $report.Stage='InitialCheckpoint';Write-RideDefaultWallpaperVmRecord (Join-Path $store 'prepare-intent.json') $report
      Restore-VMSnapshot -VMSnapshot $owned.Target.Snapshot -Confirm:$false -ErrorAction Stop
      Start-VM -VM $owned.Target.VM -ErrorAction Stop|Out-Null
    }elseif(-not $retryReset -and $owned.Target.VM.State -ne 'Running'){throw 'Retained phases require the guest to remain running; preserve evidence and inspect its state.'}
    if(-not $retryReset){$report.Stage='GuestReadiness';$null=Wait-RideDefaultWallpaperVmReady $context.Configuration $credential $descriptor;$ready=$true}
    if($Phase -cin @('Prepare','Apply','Restore') -or $userPhase){
      if($Phase -cne 'Prepare'){$null=@(Get-RideDefaultWallpaperVmPayload (Join-Path $store 'snapshot') $descriptor.Manifest);$payload=$null}
      if($Phase -ceq 'RemoveUser'){
        $report.Stage='PreCleanupExport'
        $report.PreCleanupExport=Export-RideDefaultWallpaperVmEvidence $context.Configuration $credential $descriptor $store
        if($report.PreCleanupExport.Verified -ne $true -or $report.PreCleanupExport.GuestStatus -cne 'Collected' -or $report.PreCleanupExport.FileCount -lt 1){throw 'Export before owned-user cleanup did not verify.'}
        Write-RideDefaultWallpaperVmRecord (Join-Path $store ('user-cleanup-export.'+[guid]::NewGuid().ToString('N')+'.json')) ([pscustomobject]@{SchemaVersion=1;RunId=$RunId;LeaseId=$owned.Hold.LeaseId;Purpose=$Purpose;Export=$report.PreCleanupExport})
      }
      $report.Stage=$Phase
      $guest=Invoke-RideDefaultWallpaperVmRemote $context.Configuration $credential $Phase $descriptor $payload -Purpose $Purpose -UserPassword $UserPassword
      $report.GuestResult=$guest
      Assert-RideDefaultWallpaperVmGuestResult $guest $Phase $descriptor $Purpose
      $report.Status=$guest.Status
    }else{$report.Status='Collected'}
    $report.Stage='EvidenceExport'
    $report.EvidenceExport=if($retryReset){Read-RideDefaultWallpaperVmResetExport $store $descriptor}else{Export-RideDefaultWallpaperVmEvidence $context.Configuration $credential $descriptor $store}
    if($report.EvidenceExport.Verified -ne $true -or (($Phase -cin @('Prepare','Apply','Restore') -or $userPhase) -and ($report.EvidenceExport.GuestStatus -cne 'Collected' -or $report.EvidenceExport.FileCount -lt 1))){throw 'Required guest evidence was not exported.'}
    if($Phase -ceq 'Reset'){
      $report.Stage='ExplicitCheckpointReset'
      Write-RideDefaultWallpaperVmRecord (Join-Path $store ('reset-intent.'+[guid]::NewGuid().ToString('N')+'.json')) ([pscustomobject]@{SchemaVersion=1;Kind='DefaultWallpaperVmResetIntent';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;ExportPath=$report.EvidenceExport.Path})
      Reset-RideAutomationVm $context.Configuration
      $checked=Import-RideAutomationLab $context.Configuration
      if($checked.VM.State -ne 'Off'){throw 'Explicit checkpoint recovery did not leave the pinned guest Off.'}
      $receipt=[pscustomobject]@{SchemaVersion=1;Kind='RetainedGuestRecovery';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;VMId=$owned.Hold.VMId;CheckpointId=$owned.Hold.CheckpointId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;EvidenceExportVerified=$true;CheckpointResetVerified=$true;Status='ResetAndOff';ExportPath=$report.EvidenceExport.Path}
      $receiptPath=Join-Path $store ('recovery.'+[guid]::NewGuid().ToString('N')+'.json')
      Write-RideDefaultWallpaperVmRecord $receiptPath $receipt
      $report.Status='ResetAndOff';$release=$true
    }
    $report.Stage='Retained'
  }catch{
    $report.Status='Failed';$report.Error=$_.Exception.Message
    if($ready -and $report.Stage -cin @('Prepare','Apply','Restore','CreateUser','InspectUser','RemoveUser')){
      try{$report.EvidenceExport=Export-RideDefaultWallpaperVmEvidence $context.Configuration $credential $descriptor $store}catch{$report.Error+='; Partial evidence export failed: '+$_.Exception.Message}
    }
  }
  finally{
    try{if(Test-Path -LiteralPath $store -PathType Container){Write-RideDefaultWallpaperVmRecord (Join-Path $store ('phase.'+[guid]::NewGuid().ToString('N')+'.json')) $report}}finally{$owned.Lock.Dispose()}
  }
  if($release){
    try{$released=Remove-RideRetainedGuestHold -ConfigurationPath $ConfigurationPath -RunId $RunId -RecoveryReceiptPath $receiptPath -Confirm:$false;if($released.Status -cne 'Released'){throw 'Hold release did not complete.'};$report.RecoveryRequired=$false;$report.Stage='Released'}catch{$report.Status='Failed';$report.Stage='HoldRelease';$report.Error=$_.Exception.Message}
    Write-RideDefaultWallpaperVmRecord (Join-Path $store ('release.'+[guid]::NewGuid().ToString('N')+'.json')) $report
  }
  $report
}
Register-ArgumentCompleter -CommandName Invoke-RideDefaultWallpaperVmPhase -ParameterName RunId -ScriptBlock {
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  if($fakeBoundParameters.Phase -eq 'Prepare'){return}
  & (Get-Module RIDE.RetainedGuest) {param($c,$p,$w,$a,$b) & $script:RetainedRunCompleter $c $p $w $a $b} $commandName $parameterName $wordToComplete $commandAst $fakeBoundParameters
}
Export-ModuleMember -Function Invoke-RideDefaultWallpaperVmPhase
