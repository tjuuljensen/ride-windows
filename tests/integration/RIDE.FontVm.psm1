<#
.SYNOPSIS
  Dispatch explicit machine-font acceptance phases to a retained disposable VM.
.DESCRIPTION
  Uses the registered lab credential and PowerShell Direct. Stages only five
  required source/data files and 14 pinned fonts plus their license. A durable
  controller hold survives every phase and failure. Reset requires verified export.
  Prepare can reuse its own verified snapshot only before checkpoint intent, while Off.
.NOTES
  Native Windows PowerShell 5.1 x64 host with existing elevation. Version: 0.1.3.
  Phase reports expose snapshot paths, sizes and hashes without source bytes.
  No UAC, task registration, reboot or cross-session acceptance inference. Remote jobs
  are bounded; host Hyper-V/dependency calls retain their existing API behavior.
.LINK
  ../../docs/machine-fonts.md
#>
$ErrorActionPreference='Stop'
$script:AutomationModule=Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -PassThru -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.RetainedGuest.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.FontAcceptance.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.FontFiles.psm1') -ErrorAction Stop
$script:FontVmSources=@('modules/RIDE.PrivateFiles.psm1','modules/RIDE.FontFiles.psm1','modules/RIDE.MachineFonts.psm1','tests/integration/RIDE.FontAcceptance.psm1','inputs/fonts.psd1')

function Get-RideFontVmHash {
  param([byte[]]$Bytes)
  $sha=[Security.Cryptography.SHA256]::Create()
  try{[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','')}finally{$sha.Dispose()}
}
function New-RideFontVmDirectory {
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
function Write-RideFontVmRecord {
  param([string]$Path,$Record)
  & (Get-Module RIDE.RetainedGuest) {param($p,$r) Write-RideRetainedRecord $p $r} $Path $Record
}
function Read-RideFontVmRecord {
  param([string]$Path)
  & (Get-Module RIDE.RetainedGuest) {param($p) Read-RideRetainedRecord $p} $Path
}
function Get-RideFontVmContext {
  param([string]$ConfigurationPath,[bool]$Mutation)
  & (Get-Module RIDE.RetainedGuest) {param($p,$m) Get-RideRetainedConfiguration $p $m} $ConfigurationPath $Mutation
}
function Get-RideFontVmExpectedPaths {
  $pin=Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '../fixtures/machine-fonts.acceptance.psd1')
  @($script:FontVmSources)+@(@($pin.Fonts)+@($pin.License)|ForEach-Object {'inputs/'+$_.Path})
}
function Get-RideFontVmInputs {
  param([string]$InputDirectory)
  $pin=Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '../fixtures/machine-fonts.acceptance.psd1')
  if($pin.SchemaVersion -ne 1 -or @($pin.Fonts).Count -ne 14){throw 'Font fixture schema or batch differs.'}
  $files=@();$selection=@();$total=0L
  foreach($entry in @($pin.Fonts)+@($pin.License)){
    if($entry.Path -cnotmatch '^[A-Za-z0-9_.-]+$' -or $entry.Path -in @('.','..')){throw 'Invalid fixed font input name.'}
    $source=Join-Path $InputDirectory $entry.Path
    $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $source
    $file=Get-Item -LiteralPath $source -Force
    $limit=if($entry -eq $pin.License){1048576}else{16777216}
    if($file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt $limit -or (Get-FileHash -LiteralPath $source).Hash -cne $entry.Sha256){throw 'Selected font/license pin differs.'}
    $total+=$file.Length;if($total -gt 9437184){throw 'Font fixture exceeds its bound.'}
    if($entry -ne $pin.License){
      $font=Get-RideTrueTypeMetadata -Path $source
      if($font.Sha256 -cne $entry.Sha256 -or $font.FileName -cne $entry.Path -or $font.FontLoadPerformed -or $font.InstallationPerformed){throw 'Font source identity differs.'}
      $selection+=$font|Select-Object FileName,RegistryName,FullName,Sha256
    }
    $files+=[pscustomobject]@{Path=('inputs/'+$entry.Path);Source=$source;Bytes=$file.Length;Sha256=$entry.Sha256}
  }
  [pscustomobject]@{Files=$files;Selection=$selection}
}

function Get-RideFontVmCredential {
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
function New-RideFontVmSnapshot {
  param([string]$Repository,[string]$Directory,$Inputs)
  New-RideFontVmDirectory $Directory
  $selected=@(foreach($relative in $script:FontVmSources){
    $source=if($relative -ceq 'inputs/fonts.psd1'){Join-Path $Repository 'tests/fixtures/machine-fonts.acceptance.psd1'}else{Join-Path $Repository $relative}
    [pscustomobject]@{Path=$relative;Source=$source}
  })+@($Inputs.Files)
  if((($selected.Path|Sort-Object) -join ';') -cne ((Get-RideFontVmExpectedPaths|Sort-Object) -join ';')){throw 'Snapshot input selection differs.'}
  $files=@();$total=0L
  foreach($entry in $selected){
    $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $entry.Source
    if((Get-Item -LiteralPath $entry.Source).Length -gt 16777216){throw 'Snapshot source exceeds its bound.'}
    $bytes=[IO.File]::ReadAllBytes($entry.Source);$total+=$bytes.Length
    if($bytes.Length -lt 1 -or $bytes.Length -gt 16777216 -or $total -gt 16777216){throw 'Snapshot exceeds its bound.'}
    $hash=Get-RideFontVmHash $bytes
    if($entry.Path -like 'inputs/*' -and $entry.Path -cne 'inputs/fonts.psd1' -and ($hash -cne $entry.Sha256 -or $bytes.Length -ne $entry.Bytes)){throw 'Selected input changed during snapshot creation.'}
    $path=Join-Path $Directory $entry.Path;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    $stream=[IO.File]::Open($path,'CreateNew','Write','None')
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $files+=[pscustomobject]@{Path=$entry.Path;Bytes=$bytes.Length;Sha256=$hash}
  }
  $files
}

function Get-RideFontVmPayload {
  param([string]$Directory,$Manifest)
  $expected=@(Get-RideFontVmExpectedPaths)
  if(@($Manifest).Count -ne $expected.Count -or (@($Manifest.Path|Sort-Object) -join ';') -cne (@($expected|Sort-Object) -join ';')){throw 'Snapshot source selection differs.'}
  foreach($entry in $Manifest){
    $path=Join-Path $Directory $entry.Path
    $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.Bytes -or $entry.Bytes -gt 16777216){throw 'Retained snapshot size changed.'}
    $bytes=[IO.File]::ReadAllBytes($path)
    if($bytes.Length -ne $entry.Bytes -or (Get-RideFontVmHash $bytes) -cne $entry.Sha256){throw 'Retained snapshot bytes changed.'}
    [pscustomobject]@{Path=$entry.Path;Bytes=$entry.Bytes;Sha256=$entry.Sha256;Content=[Convert]::ToBase64String($bytes)}
  }
}

# This scriptblock is the only remote dispatch target. Neither queue data nor
# caller input supplies PowerShell source, command names, or filesystem roots.
$script:FontVmRemote={
  param($Action,$Descriptor,$Payload)
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
  $expectedSources=@('modules/RIDE.PrivateFiles.psm1','modules/RIDE.FontFiles.psm1','modules/RIDE.MachineFonts.psm1','tests/integration/RIDE.FontAcceptance.psm1','inputs/fonts.psd1','inputs/OpenSauceSans-Black.ttf','inputs/OpenSauceSans-BlackItalic.ttf','inputs/OpenSauceSans-Bold.ttf','inputs/OpenSauceSans-BoldItalic.ttf','inputs/OpenSauceSans-ExtraBold.ttf','inputs/OpenSauceSans-ExtraBoldItalic.ttf','inputs/OpenSauceSans-Italic.ttf','inputs/OpenSauceSans-Light.ttf','inputs/OpenSauceSans-LightItalic.ttf','inputs/OpenSauceSans-Medium.ttf','inputs/OpenSauceSans-MediumItalic.ttf','inputs/OpenSauceSans-Regular.ttf','inputs/OpenSauceSans-SemiBold.ttf','inputs/OpenSauceSans-SemiBoldItalic.ttf','inputs/OFL.txt')
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
    if(-not (Test-Path -LiteralPath $base)){return [pscustomobject]@{SchemaVersion=1;Kind='FontVmCollection';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Absent';Context=$context;Files=@()}}
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
    $beforePath=Join-Path $base ('evidence/'+$Descriptor.RunId+'/before.json')
    if(Test-Path -LiteralPath $beforePath){
      foreach($entry in $Descriptor.Manifest){
        $path=Join-Path (Join-Path $base 'source') $entry.Path
        $file=Get-Item -LiteralPath $path -Force
        if($file.PSIsContainer -or $file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.Length -ne $entry.Bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.Sha256){throw 'Staged source changed before read-only font observation.'}
      }
      $acceptance=Import-Module (Join-Path $base 'source/tests/integration/RIDE.FontAcceptance.psm1') -PassThru -Force
      $observation=& $acceptance {
        param($BeforePath,$Selection)
        $beforeBytes=Read-RidePrivateFileBytes -Path $BeforePath -Scope Machine -MaximumBytes 16777216
        $before=[Text.UTF8Encoding]::new($false,$true).GetString($beforeBytes)|ConvertFrom-Json
        $current=Get-RideFontAcceptanceSnapshot (Get-RideFontAcceptanceContext) $Selection
        [pscustomobject]@{
          FilesMatchInitial=(Test-RideFontAcceptanceEqual $before.Files $current.Files)
          RegistryRowsMatchInitial=(Test-RideFontAcceptanceEqual $before.Registry.Rows $current.Registry.Rows)
          RegistrySecurityMatchesInitial=($before.Registry.Security -ceq $current.Registry.Security)
          NativeNamesMatchInitial=(Test-RideFontAcceptanceEqual $before.NativeNames $current.NativeNames)
          CurrentSelectedNativeNames=@($current.NativeNames)
          CurrentSelectedFilesPresent=@($current.Files|Where-Object {$_.File.Exists}).Count
          CurrentSelectedRegistrationsPresent=@($current.Files|Where-Object {$null -ne $_.Registration}).Count
        }
      } $beforePath $Descriptor.Selection
      $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($observation|ConvertTo-Json -Depth 5))
      $total+=$bytes.Length
      if($total -gt 33554432 -or $files.Count -ge 512){throw 'Font observation exceeds collection bounds.'}
      $files.Add([pscustomobject]@{Path='collection-font-observation.json';Bytes=$bytes.Length;Sha256=(Get-Hash $bytes);Content=[Convert]::ToBase64String($bytes)})
    }
    return [pscustomobject]@{SchemaVersion=1;Kind='FontVmCollection';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Collected';Context=$context;Files=$files.ToArray()}
  }
  Assert-Directory $base
  foreach($entry in $Descriptor.Manifest){
    $path=Join-Path (Join-Path $base 'source') $entry.Path
    $file=Get-Item -LiteralPath $path -Force
    if($file.PSIsContainer -or $file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.Length -ne $entry.Bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.Sha256){throw 'Staged guest source changed.'}
  }
  Import-Module (Join-Path $base 'source/tests/integration/RIDE.FontAcceptance.psm1') -Force
  Import-Module (Join-Path $base 'source/modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop
  $env:RIDE_INTEGRATION_VM='1';$env:RIDE_TEST_GUEST='1';$env:RIDE_TEST_RUN_ID=$Descriptor.RunId
  $metadata=Join-Path $base 'prepared.json'
  if($Action -ceq 'Prepare'){
    & (Get-Module RIDE.FontAcceptance) {param($p,$r) Save-RideFontAcceptanceReport $p $r} $metadata ([pscustomobject]@{RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Context=$context})
    return [pscustomobject]@{SchemaVersion=1;Kind='FontVmPreparation';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Prepared';Context=$context;NativeAcceptancePassed=$false}
  }
  $bytes=Read-RidePrivateFileBytes -Path $metadata -Scope Machine -MaximumBytes 1048576
  $prepared=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
  if($prepared.RunId -cne $Descriptor.RunId -or $prepared.LeaseId -cne $Descriptor.LeaseId -or $prepared.Context.Revision -ne $context.Revision){throw 'Prepared guest identity/build revision changed.'}
  if($Action -cne 'Lifecycle'){throw 'Unknown fixed guest phase.'}
  Invoke-RideFontAcceptance -RunId $Descriptor.RunId -ManifestPath (Join-Path $base 'source/inputs/fonts.psd1') -ExpectedComputerName $context.ComputerName -ExpectedBuild $Descriptor.ExpectedBuild -ExpectedEditionId $Descriptor.ExpectedEditionId -EvidenceRoot (Join-Path $base 'evidence') -DisposableVm -Confirm:$false
}

function Invoke-RideFontVmRemote {
  param($Configuration,[pscredential]$Credential,[string]$Action,$Descriptor,$Payload,[int]$TimeoutSeconds=180)
  $job=Invoke-Command -VMId ([guid]$Configuration.VMId) -Credential $Credential -ScriptBlock $script:FontVmRemote -ArgumentList $Action,$Descriptor,$Payload -AsJob -ErrorAction Stop
  try{
    if(-not (Wait-Job $job -Timeout $TimeoutSeconds)){throw 'Remote phase timed out; retain the guest and hold for inspection.'}
    $result=@(Receive-Job $job -ErrorAction Stop)
    if($job.State -ne 'Completed' -or $result.Count -ne 1){throw 'Remote phase did not return one completed result.'}
    $result[0]
  }finally{Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}
}
function Wait-RideFontVmReady {
  param($Configuration,[pscredential]$Credential,$Descriptor)
  $deadline=[datetime]::UtcNow.AddMinutes(3)
  do{
    try{return Invoke-RideFontVmRemote $Configuration $Credential Ready $Descriptor $null 15}catch{if([datetime]::UtcNow -ge $deadline){throw 'Guest readiness/target verification did not complete within three minutes.'};Start-Sleep -Seconds 2}
  }while($true)
}
function Export-RideFontVmEvidence {
  param($Configuration,[pscredential]$Credential,$Descriptor,[string]$Store)
  $collected=Invoke-RideFontVmRemote $Configuration $Credential Collect $Descriptor $null
  if($collected.SchemaVersion -ne 1 -or $collected.Kind -cne 'FontVmCollection' -or $collected.RunId -cne $Descriptor.RunId -or $collected.LeaseId -cne $Descriptor.LeaseId -or
    $collected.Status -cnotin @('Collected','Absent') -or $collected.Context.ComputerName -ine $Descriptor.VMName -or $collected.Context.Build -cne $Descriptor.ExpectedBuild -or $collected.Context.EditionId -cne $Descriptor.ExpectedEditionId){throw 'Unexpected or mismatched guest collection result.'}
  $export=Join-Path $Store ('export.'+[guid]::NewGuid().ToString('N'));New-RideFontVmDirectory $export
  $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L;$manifest=@()
  if(@($collected.Files).Count -gt 512){throw 'Export file count exceeds its bound.'}
  foreach($entry in $collected.Files){
    if($entry.Path -notmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -or @($entry.Path -split '/'|Where-Object {$_ -in @('.','..')}).Count -or -not $names.Add($entry.Path)){throw 'Unsafe or duplicate guest evidence path.'}
    if($entry.Bytes -lt 0 -or $entry.Bytes -gt 16777216 -or $entry.Content.Length -gt 22369624){throw 'Guest evidence encoding exceeds its bound.'}
    $bytes=[Convert]::FromBase64String($entry.Content);$total+=$bytes.Length
    if($bytes.Length -gt 16777216 -or $total -gt 33554432 -or $bytes.Length -ne $entry.Bytes -or (Get-RideFontVmHash $bytes) -cne $entry.Sha256){throw 'Guest evidence bytes differ or exceed their bound.'}
    $destination=Join-Path $export $entry.Path;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
    $stream=[IO.File]::Open($destination,'CreateNew','Write','None');try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if((Get-FileHash -LiteralPath $destination).Hash -cne $entry.Sha256){throw 'Exported evidence digest differs.'}
    $manifest+=@([pscustomobject]@{Path=$entry.Path;Bytes=$entry.Bytes;Sha256=$entry.Sha256})
  }
  if($collected.Status -ceq 'Absent' -and $manifest.Count){throw 'Absent guest export contains files.'}
  $receipt=[pscustomobject]@{SchemaVersion=1;Kind='RetainedGuestExport';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status=$collected.Status;Files=$manifest;Context=$collected.Context;RecordedAtUtc=[datetime]::UtcNow.ToString('o')}
  Write-RideFontVmRecord (Join-Path $export 'export-receipt.json') $receipt
  $observationPath=Join-Path $export 'collection-font-observation.json'
  # Export files inherit the already validated private directory ACL. Their
  # bytes were bounded, hashed and read back above; they are not journal files.
  $observation=if(Test-Path -LiteralPath $observationPath){[IO.File]::ReadAllText($observationPath,[Text.UTF8Encoding]::new($false,$true))|ConvertFrom-Json}else{$null}
  [pscustomobject]@{Verified=$true;Path=$export;FileCount=$manifest.Count;GuestStatus=$collected.Status;FontObservation=$observation}
}
function Read-RideFontVmResetExport {
  param([string]$Store,$Descriptor)
  $intents=@(Get-ChildItem -LiteralPath $Store -Filter 'reset-intent.*.json' -File|Select-Object -First 513)
  if(-not $intents.Count -or $intents.Count -gt 512){throw 'An Off guest requires a retained pre-reset export intent.'}
  $intent=Read-RideFontVmRecord ($intents|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1).FullName
  if($intent.SchemaVersion -ne 1 -or $intent.Kind -cne 'FontVmResetIntent' -or $intent.RunId -cne $Descriptor.RunId -or $intent.LeaseId -cne $Descriptor.LeaseId -or $intent.ConfigurationSha256 -cne $Descriptor.ConfigurationSha256){throw 'Saved reset/export intent differs.'}
  $leaf=Split-Path -Leaf $intent.ExportPath
  if($leaf -cnotmatch '^export\.[a-f0-9]{32}$' -or $intent.ExportPath -cne (Join-Path $Store $leaf)){throw 'Saved export path escaped its retained store.'}
  $receipt=Read-RideFontVmRecord (Join-Path $intent.ExportPath 'export-receipt.json')
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
function Assert-RideFontVmGuestResult {
  param($Guest,[string]$Phase,$Descriptor)
  if($Guest.SchemaVersion -ne 1 -or $Guest.RunId -cne $Descriptor.RunId -or $Guest.NativeAcceptancePassed -isnot [bool]){throw 'Guest phase correlation or acceptance boundary differs.'}
  if($Phase -ceq 'Prepare'){
    if($Guest.Kind -cne 'FontVmPreparation' -or $Guest.Status -cne 'Prepared' -or $Guest.LeaseId -cne $Descriptor.LeaseId -or $Guest.NativeAcceptancePassed){throw 'Guest preparation result differs.'}
    return
  }
  if($Guest.Kind -cne 'MachineFontAcceptance' -or $Guest.ComputerName -ine $Descriptor.VMName -or $Guest.Build -cne $Descriptor.ExpectedBuild -or $Guest.EditionId -cne $Descriptor.ExpectedEditionId -or $Guest.CrossSessionAcceptancePassed -ne $false -or $Guest.RestartAcceptancePassed -ne $false){throw 'Guest font target or acceptance boundary differs.'}
  if($Guest.Status -ceq 'NotRun'){
    if($Guest.Reason -cnotin @('ExistingElevationRequired','SelectedFontsMustBeInitiallyAbsent') -or $Guest.NativeAcceptancePassed -or $Guest.RecoveryRequired -or @($Guest.Checks).Count -or @($Guest.LifecycleRuns).Count -or @($Guest.StateRunIds).Count){throw 'Invalid unrun font result.'}
    return
  }
  $checks='PreviewNoChanges;InstalledNativeNamesFilesRegistrationAndPrivateState;RepeatNoChanges;RemovedToInitialState;InstalledBytesPermissionsMetadataAndNativeNamesRestored;InitialStateRestored;RepeatedRestoreNoChanges'
  if($Guest.Status -cne 'Passed' -or $Guest.Stage -cne 'Complete' -or -not $Guest.NativeAcceptancePassed -or $Guest.RecoveryRequired -or ($Guest.Checks -join ';') -cne $checks){throw 'Guest phase did not establish every required lifecycle check.'}
  $actual=@($Guest.Selection|Select-Object FileName,RegistryName,FullName,Sha256)|ConvertTo-Json -Depth 4 -Compress
  $expected=@($Descriptor.Selection|Select-Object FileName,RegistryName,FullName,Sha256)|ConvertTo-Json -Depth 4 -Compress
  if(@($Guest.Selection).Count -ne 14 -or $actual -cne $expected){throw 'Guest font selection differs.'}
  if(@($Guest.LifecycleRuns).Count -ne 2 -or ($Guest.LifecycleRuns.Action -join ';') -cne 'Install;Remove' -or
    @($Guest.LifecycleRuns|Where-Object {$_.Restored -ne $true -or $_.RunId -cnotmatch '^[a-f0-9]{32}$'}).Count -or
    @($Guest.LifecycleRuns.RunId|Select-Object -Unique).Count -ne 2 -or
    (@($Guest.StateRunIds|Sort-Object) -join ';') -cne (@($Guest.LifecycleRuns.RunId|Sort-Object) -join ';')){throw 'Guest font recovery runs are incomplete.'}
}

function Invoke-RideFontVmPhase {
  <#
  .SYNOPSIS
    Prepare, run current-session font lifecycle, collect or reset the retained VM.
  .PARAMETER Phase
    Prepare reserves/stages/starts the clean VM; Lifecycle performs all seven
    current-session checks and both captured restores in one guest session. Collect exports evidence. Reset exports before
    restoring the pinned checkpoint and releasing the hold; it does not pass tests.
  .PARAMETER ConfigurationPath
    Installed controller configuration for the owning elevated host account.
  .PARAMETER RunId
    New request ID for Prepare; reuse for later phases. Completion reads the hold.
  .PARAMETER InputDirectory
    Prepare-only directory containing the 14 pinned fonts and OFL.txt.
  .PARAMETER ExpectedBuild
    Prepare-only exact Windows 11 guest build, at least 22000.
  .PARAMETER ExpectedEditionId
    Prepare-only exact Enterprise/Education guest edition.
  .EXAMPLE
    Invoke-RideFontVmPhase -Phase Prepare -ConfigurationPath '<installed-configuration>' -RunId '<request-id>' -InputDirectory '<selected-font-directory>' -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -WhatIf
  .OUTPUTS
    Schema-1 phase report; CurrentSessionAcceptancePassed requires all seven checks.
    NativeAcceptancePassed stays false until broader evidence exists. Failures retain
    the guest, hold and private records; no automatic checkpoint cleanup runs.
  .NOTES
    Use the registered checkout in an already elevated Windows PowerShell 5.1
    process. Direct invocation only; do not submit through the generic queue.
    Current-session lifecycle is separate from restart, other sessions and consumers.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidateSet('Prepare','Lifecycle','Collect','Reset')][string]$Phase,
    [Parameter(Mandatory)][string]$ConfigurationPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId,
    [string]$InputDirectory,[ValidatePattern('^\d{5,8}$')][string]$ExpectedBuild,
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
    if(-not $InputDirectory -or -not $ExpectedEditionId -or -not $ExpectedBuild -or [int]$ExpectedBuild -lt 22000){throw 'Prepare requires the selected source, exact Windows 11 build and edition.'}
  }elseif($InputDirectory -or $ExpectedBuild -or $ExpectedEditionId){throw 'Source and target selections belong only to Prepare.'}
  $context=Get-RideFontVmContext $ConfigurationPath (-not $WhatIfPreference)
  $repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\')
  if([IO.Path]::GetFullPath($context.Configuration.LocalRepositoryPath).TrimEnd('\') -ine $repository){throw 'Use the registered checkout for retained dispatch.'}
  $inputs=if($Phase -ceq 'Prepare'){Get-RideFontVmInputs $InputDirectory}else{$null}
  if(-not $PSCmdlet.ShouldProcess($context.Configuration.VMName,"Run explicit retained machine-font $Phase phase")){return [pscustomobject]@{SchemaVersion=1;RunId=$RunId;Phase=$Phase;Status='Preview';NativeAcceptancePassed=$false}}
  $retryPrepare=($Phase -ceq 'Prepare' -and (Test-Path -LiteralPath (Join-Path $context.Root 'runtime/blocked.json')))
  if($Phase -ceq 'Prepare' -and -not $retryPrepare){$null=New-RideRetainedGuestHold -ConfigurationPath $ConfigurationPath -RunId $RunId -Confirm:$false}
  $owned=Open-RideRetainedGuestPhase -ConfigurationPath $ConfigurationPath -RunId $RunId
  $store=Join-Path $context.Root ('retained.'+$owned.Hold.LeaseId)
  $report=[pscustomobject][ordered]@{SchemaVersion=1;RunId=$RunId;LeaseId=$owned.Hold.LeaseId;Phase=$Phase;Status='Failed';Stage='Preflight';NativeAcceptancePassed=$false;CurrentSessionAcceptancePassed=$false;CrossSessionAcceptancePassed=$false;RestartAcceptancePassed=$false;ActiveConsumerAcceptancePassed=$false;RecoveryRequired=$true;EvidenceExport=$null;GuestResult=$null;Error=$null;Store=$store;RecordedAtUtc=[datetime]::UtcNow.ToString('o')}
  $release=$false;$ready=$false
  try{
    if($context.ConfigurationSha256 -cne $owned.Context.ConfigurationSha256){throw 'Controller configuration changed before phase ownership.'}
    if($Phase -ceq 'Prepare' -and -not $retryPrepare){
      New-RideFontVmDirectory $store
      $manifest=@(New-RideFontVmSnapshot $repository (Join-Path $store 'snapshot') $inputs)
      $descriptor=[pscustomobject]@{SchemaVersion=1;Kind='FontVmSession';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;VMName=$context.Configuration.VMName;VMId=$owned.Hold.VMId;CheckpointId=$owned.Hold.CheckpointId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;Manifest=$manifest;Selection=$inputs.Selection}
      Write-RideFontVmRecord (Join-Path $store 'session.json') $descriptor
    }else{
      $descriptor=Read-RideFontVmRecord (Join-Path $store 'session.json')
      foreach($name in @('RunId','LeaseId','VMId','VMName','CheckpointId','ConfigurationSha256')){if($descriptor.$name -cne $owned.Hold.$name){throw 'Saved VM session identity differs.'}}
      if($descriptor.SchemaVersion -ne 1 -or $descriptor.Kind -cne 'FontVmSession'){throw 'Saved VM session schema differs.'}
    }
    if($retryPrepare){
      if((Test-Path -LiteralPath (Join-Path $store 'prepare-intent.json')) -or $owned.Target.VM.State -ne 'Off'){throw 'Prepare retry requires an Off guest with no prior checkpoint intent.'}
      if($descriptor.ExpectedBuild -cne $ExpectedBuild -or $descriptor.ExpectedEditionId -cne $ExpectedEditionId){throw 'Prepare retry target selection differs.'}
      $savedSelection=@($descriptor.Selection|Select-Object FileName,RegistryName,FullName,Sha256)|ConvertTo-Json -Depth 4 -Compress
      $requestedSelection=@($inputs.Selection|Select-Object FileName,RegistryName,FullName,Sha256)|ConvertTo-Json -Depth 4 -Compress
      if($savedSelection -cne $requestedSelection){throw 'Prepare retry font selection differs.'}
    }
    $report|Add-Member -NotePropertyName SourceManifest -NotePropertyValue @($descriptor.Manifest|Select-Object Path,Bytes,Sha256)
    $retryReset=($Phase -ceq 'Reset' -and $owned.Target.VM.State -eq 'Off')
    $credential=if(-not $retryReset){Get-RideFontVmCredential $context.Configuration}else{$null}
    if($Phase -ceq 'Prepare'){
      $payload=@(Get-RideFontVmPayload (Join-Path $store 'snapshot') $descriptor.Manifest)
      if($owned.Target.VM.State -ne 'Off'){throw 'Prepare requires the reserved VM to remain Off.'}
      $report.Stage='InitialCheckpoint';Write-RideFontVmRecord (Join-Path $store 'prepare-intent.json') $report
      Restore-VMSnapshot -VMSnapshot $owned.Target.Snapshot -Confirm:$false -ErrorAction Stop
      Start-VM -VM $owned.Target.VM -ErrorAction Stop|Out-Null
    }elseif(-not $retryReset -and $owned.Target.VM.State -ne 'Running'){throw 'Retained phases require the guest to remain running; preserve evidence and inspect its state.'}
    if(-not $retryReset){$report.Stage='GuestReadiness';$null=Wait-RideFontVmReady $context.Configuration $credential $descriptor;$ready=$true}
    if($Phase -cin @('Prepare','Lifecycle')){
      if($Phase -cne 'Prepare'){$null=@(Get-RideFontVmPayload (Join-Path $store 'snapshot') $descriptor.Manifest);$payload=$null}
      $report.Stage=$Phase
      $guest=Invoke-RideFontVmRemote $context.Configuration $credential $Phase $descriptor $payload
      $report.GuestResult=$guest
      Assert-RideFontVmGuestResult $guest $Phase $descriptor
      $report.Status=$guest.Status
      if($Phase -ceq 'Lifecycle' -and $guest.Status -ceq 'Passed'){$report.CurrentSessionAcceptancePassed=$true}
    }else{$report.Status='Collected'}
    $report.Stage='EvidenceExport'
    $report.EvidenceExport=if($retryReset){Read-RideFontVmResetExport $store $descriptor}else{Export-RideFontVmEvidence $context.Configuration $credential $descriptor $store}
    if($report.EvidenceExport.Verified -ne $true -or ($Phase -cin @('Prepare','Lifecycle') -and ($report.EvidenceExport.GuestStatus -cne 'Collected' -or $report.EvidenceExport.FileCount -lt 1))){throw 'Required guest evidence was not exported.'}
    if($Phase -ceq 'Reset'){
      $report.Stage='ExplicitCheckpointReset'
      Write-RideFontVmRecord (Join-Path $store ('reset-intent.'+[guid]::NewGuid().ToString('N')+'.json')) ([pscustomobject]@{SchemaVersion=1;Kind='FontVmResetIntent';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;ExportPath=$report.EvidenceExport.Path})
      Reset-RideAutomationVm $context.Configuration
      $checked=Import-RideAutomationLab $context.Configuration
      if($checked.VM.State -ne 'Off'){throw 'Explicit checkpoint recovery did not leave the pinned guest Off.'}
      $receipt=[pscustomobject]@{SchemaVersion=1;Kind='RetainedGuestRecovery';RunId=$RunId;LeaseId=$owned.Hold.LeaseId;VMId=$owned.Hold.VMId;CheckpointId=$owned.Hold.CheckpointId;ConfigurationSha256=$owned.Hold.ConfigurationSha256;EvidenceExportVerified=$true;CheckpointResetVerified=$true;Status='ResetAndOff';ExportPath=$report.EvidenceExport.Path}
      $receiptPath=Join-Path $store ('recovery.'+[guid]::NewGuid().ToString('N')+'.json')
      Write-RideFontVmRecord $receiptPath $receipt
      $report.Status='ResetAndOff';$release=$true
    }
    $report.Stage='Retained'
  }catch{
    $report.Status='Failed';$report.CurrentSessionAcceptancePassed=$false;$report.Error=$_.Exception.Message
    if($ready -and $report.Stage -cin @('Prepare','Lifecycle')){
      try{$report.EvidenceExport=Export-RideFontVmEvidence $context.Configuration $credential $descriptor $store}catch{$report.Error+='; Partial evidence export failed: '+$_.Exception.Message}
    }
  }
  finally{
    try{if(Test-Path -LiteralPath $store -PathType Container){Write-RideFontVmRecord (Join-Path $store ('phase.'+[guid]::NewGuid().ToString('N')+'.json')) $report}}finally{$owned.Lock.Dispose()}
  }
  if($release){
    try{$released=Remove-RideRetainedGuestHold -ConfigurationPath $ConfigurationPath -RunId $RunId -RecoveryReceiptPath $receiptPath -Confirm:$false;if($released.Status -cne 'Released'){throw 'Hold release did not complete.'};$report.RecoveryRequired=$false;$report.Stage='Released'}catch{$report.Status='Failed';$report.Stage='HoldRelease';$report.Error=$_.Exception.Message}
    Write-RideFontVmRecord (Join-Path $store ('release.'+[guid]::NewGuid().ToString('N')+'.json')) $report
  }
  $report
}
Register-ArgumentCompleter -CommandName Invoke-RideFontVmPhase -ParameterName RunId -ScriptBlock {
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  if($fakeBoundParameters.Phase -eq 'Prepare'){return}
  & (Get-Module RIDE.RetainedGuest) {param($c,$p,$w,$a,$b) & $script:RetainedRunCompleter $c $p $w $a $b} $commandName $parameterName $wordToComplete $commandAst $fakeBoundParameters
}
Export-ModuleMember -Function Invoke-RideFontVmPhase
