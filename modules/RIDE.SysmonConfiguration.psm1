<#
.SYNOPSIS
  Apply and restore an explicit Sysmon XML configuration with captured source bytes.
.DESCRIPTION
  Requires an existing running standalone Sysmon64 service, an explicitly pinned
  Microsoft executable, exact target identity and recoverable prior XML matching
  the latest configuration-change event. Download and package installation remain
  separate. Native acceptance is pending; changes require candidate opt-in.
.NOTES
  Compatibility: Candidate native Windows 11 x64; PowerShell 5.1 and 7.
  Prerequisites: Existing elevation, local inputs and private machine state.
  Recovery: Completed runs only; restores XML rules, not emitted events or archives.
  Version: 0.1.1. Changelog: Share executable identity validation with guarded fixture setup.
  0.1.0: Add source-bound configuration apply and recovery.
.LINK
  ../docs/sysmon-configuration.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.PrivateFiles.psm1') -ErrorAction Stop

function Get-RideSysmonHash {
  param([byte[]]$Bytes)
  $sha=[Security.Cryptography.SHA256]::Create()
  try{[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','')}finally{$sha.Dispose()}
}

function Read-RideSysmonSource {
  param([string]$Path,[string]$ExpectedSha256)
  if($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'An explicit source SHA-256 is required.'}
  $full=& (Get-Module RIDE.PrivateFiles) {param($path) Resolve-RidePrivateFilePath $path} $Path
  $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try {
    if($stream.Length -lt 1 -or $stream.Length -gt 2097152){throw 'Sysmon XML source must be between one byte and two MiB.'}
    $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if(-not $count){throw 'Sysmon source ended during read.'};$offset+=$count}
  }finally{$stream.Dispose()}
  if((Get-RideSysmonHash $bytes) -ine $ExpectedSha256){throw 'Sysmon XML source hash differs.'}
  $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=2097152
  $memory=[IO.MemoryStream]::new($bytes,$false);$reader=[Xml.XmlReader]::Create($memory,$settings)
  try{$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)}finally{$reader.Dispose();$memory.Dispose()}
  if($doc.DocumentElement.Name -cne 'Sysmon' -or $doc.DocumentElement.NamespaceURI -cne '' -or $doc.DocumentElement.GetAttribute('schemaversion') -cne '4.91'){throw 'This candidate requires an unnamespaced Sysmon schema 4.91 XML source.'}
  [pscustomobject]@{Path=$full;Sha256=(Get-RideSysmonHash $bytes);Bytes=$bytes}
}

function ConvertFrom-RideSysmonConfigurationEvent {
  param([string]$Xml)
  $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=65536
  $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings)
  try{$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)}finally{$reader.Dispose()}
  $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
  $provider=$doc.SelectSingleNode('/e:Event/e:System/e:Provider',$ns)
  if($null -eq $provider -or $provider.GetAttribute('Name') -cne 'Microsoft-Windows-Sysmon' -or $doc.SelectSingleNode('/e:Event/e:System/e:EventID',$ns).InnerText -cne '16'){throw 'Expected a Sysmon configuration-change event.'}
  $record=$doc.SelectSingleNode('/e:Event/e:System/e:EventRecordID',$ns).InnerText
  if($record -cnotmatch '^[1-9][0-9]{0,17}$'){throw 'Invalid configuration event record identity.'}
  $hashes=$doc.SelectNodes('/e:Event/e:EventData/e:Data[@Name="ConfigurationFileHash"]',$ns)
  $paths=$doc.SelectNodes('/e:Event/e:EventData/e:Data[@Name="Configuration"]',$ns)
  if($hashes.Count -ne 1 -or $paths.Count -ne 1){throw 'Configuration event source identity is unavailable.'}
  $matches=[regex]::Matches($hashes[0].InnerText,'(?i)(?:^|,)SHA256=([a-f0-9]{64})(?=,|$)')
  if($matches.Count -ne 1 -or [string]::IsNullOrWhiteSpace($paths[0].InnerText)){throw 'Configuration event requires an unambiguous SHA-256 and source path.'}
  [pscustomobject]@{RecordId=[long]$record;Sha256=$matches[0].Groups[1].Value.ToUpperInvariant();ConfigurationPath=$paths[0].InnerText}
}

function Get-RideSysmonConfigurationEvent {
  $event=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=16} -MaxEvents 1 -ErrorAction Stop
  ConvertFrom-RideSysmonConfigurationEvent $event.ToXml()
}

function Get-RideSysmonExecutableIdentity {
  param([string]$ExecutablePath,[string]$ExpectedExecutableSha256,[string]$ExpectedSysmonVersion)
  $path=& (Get-Module RIDE.PrivateFiles) {param($path) Resolve-RidePrivateFilePath $path} $ExecutablePath
  if($ExpectedExecutableSha256 -notmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $ExpectedExecutableSha256){throw 'Selected Sysmon executable hash differs.'}
  if($ExpectedSysmonVersion -notmatch '^15\.(?:2[1-9]|[3-9][0-9])$'){throw 'Select an explicit candidate Sysmon 15.21 or later 15.x version.'}
  $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($path)
  if(('{0}.{1}' -f $version.FileMajorPart,$version.FileMinorPart) -cne $ExpectedSysmonVersion){throw 'Sysmon executable version differs.'}
  $signature=Get-AuthenticodeSignature -LiteralPath $path
  if($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){throw 'A valid Microsoft Authenticode signature is required.'}
  [pscustomobject]@{Path=$path;Sha256=$ExpectedExecutableSha256.ToUpperInvariant();Version=$ExpectedSysmonVersion}
}

function Get-RideSysmonConfigurationContext {
  param([string]$ExecutablePath,[string]$ExpectedExecutableSha256,[string]$ExpectedSysmonVersion)
  $executable=Get-RideSysmonExecutableIdentity $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion
  $path=$executable.Path
  $service=Get-CimInstance Win32_Service -Filter "Name='Sysmon64'" -ErrorAction Stop
  if($null -eq $service -or $service.State -cne 'Running'){throw 'An existing running standalone Sysmon64 service is required.'}
  $match=[regex]::Match([string]$service.PathName,'^\s*(?:"(?<quoted>[^"]+)"|(?<plain>\S+\.exe))(?:\s|$)','IgnoreCase')
  $servicePath=if($match.Groups['quoted'].Success){$match.Groups['quoted'].Value}else{$match.Groups['plain'].Value}
  if(-not $match.Success -or [IO.Path]::GetFullPath($servicePath) -ine $path){throw 'Selected executable is not the running Sysmon64 service image.'}
  $windows=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{[pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$windows.CurrentBuildNumber;EditionId=[string]$windows.EditionID;Revision=[int]$windows.UBR;InstallationType=[string]$windows.InstallationType;NativeProcess=[Environment]::Is64BitProcess;Architecture=$env:PROCESSOR_ARCHITECTURE;UserSid=$identity.User.Value;Administrator=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);ExecutablePath=$path;ExecutableSha256=$ExpectedExecutableSha256.ToUpperInvariant();SysmonVersion=$ExpectedSysmonVersion;ServicePathName=[string]$service.PathName;ServiceStartMode=[string]$service.StartMode;ServiceState=[string]$service.State}}finally{$identity.Dispose()}
}

function Assert-RideSysmonConfigurationContext {
  param($Context,$Expected,[bool]$Mutation)
  if($Context.InstallationType -cne 'Client' -or $Context.Build -cnotmatch '^\d{5,8}$' -or [int]$Context.Build -lt 22000 -or -not $Context.NativeProcess -or $Context.Architecture -cne 'AMD64'){throw 'Sysmon configuration candidate requires native Windows 11 x64.'}
  if($Mutation -and -not $Context.Administrator){throw 'Sysmon configuration requires existing elevation; no UAC is launched.'}
  if($Expected){foreach($field in @('ComputerName','Build','EditionId','Revision','InstallationType','NativeProcess','Architecture','UserSid','ExecutablePath','ExecutableSha256','SysmonVersion','ServicePathName','ServiceStartMode','ServiceState')){if($Context.$field -cne $Expected.$field){throw "Sysmon context changed ($field); retain recovery evidence."}}}
}

function Assert-RideSysmonStateDirectory {
  param([string]$StateDirectory)
  $full=[IO.Path]::GetFullPath($StateDirectory)
  if(-not [IO.Directory]::Exists($full)){throw 'Create a local machine-state directory explicitly.'}
  $null=& (Get-Module RIDE.PrivateFiles) {param($path) Resolve-RidePrivateFilePath $path} (Join-Path $full 'path-validation-only')
}

function Get-RideSysmonRunPath {
  param([string]$StateDirectory,[string]$RunId,[ValidateSet('intent.json','applied.json','before.xml','after.xml')][string]$Part)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'Sysmon run ID must be 32 lowercase hexadecimal characters.'}
  Join-Path $StateDirectory ($RunId+'.sysmon.'+$Part)
}

function Save-RideSysmonPrivateBytes {
  param([string]$Path,[byte[]]$Bytes)
  $stream=New-RidePrivateFileStream -Path $Path -Scope Machine
  try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}

function Save-RideSysmonRecord {
  param([string]$StateDirectory,[string]$RunId,[string]$Part,$Record)
  Save-RideSysmonPrivateBytes (Get-RideSysmonRunPath $StateDirectory $RunId $Part) ([Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 10 -Compress)))
}

function Read-RideSysmonRecord {
  param([string]$StateDirectory,[string]$RunId,[string]$Part)
  $bytes=Read-RidePrivateFileBytes -Path (Get-RideSysmonRunPath $StateDirectory $RunId $Part) -Scope Machine -MaximumBytes 1048576
  $record=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
  if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'SysmonConfiguration' -or $record.RunId -cne $RunId -or $record.Part -cne $Part){throw 'Sysmon recovery record identity differs.'}
  $record
}

function Invoke-RideSysmonConfigurationCommand {
  param([string]$ExecutablePath,[string]$ConfigurationPath)
  if($ConfigurationPath.Contains('"')){throw 'Invalid configuration path.'}
  $process=[Diagnostics.Process]::new()
  try {
    $process.StartInfo=[Diagnostics.ProcessStartInfo]::new($ExecutablePath,('-c "'+$ConfigurationPath+'"'))
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    if(-not $process.Start()){throw 'Sysmon configuration process did not start.'}
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(30000)){$process.Kill();throw 'Sysmon configuration process timed out; inspect retained recovery state.'}
    if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Sysmon output pipes did not close within the bounded wait.'}
    $output=$stdout.GetAwaiter().GetResult();$errorOutput=$stderr.GetAwaiter().GetResult()
    if($process.ExitCode -ne 0 -or $output.Length -gt 1048576 -or $errorOutput.Length -gt 1048576){throw 'Sysmon configuration process failed or exceeded output bounds.'}
  }finally{$process.Dispose()}
}

function Wait-RideSysmonConfigurationEvent {
  param([long]$AfterRecordId,[string]$Sha256,[string]$ConfigurationPath)
  $deadline=[Diagnostics.Stopwatch]::StartNew()
  do {
    $event=Get-RideSysmonConfigurationEvent
    if($event.RecordId -gt $AfterRecordId){
      if($event.Sha256 -cne $Sha256 -or $event.ConfigurationPath -ine $ConfigurationPath){throw 'A newer configuration event does not match the selected source.'}
      return $event
    }
    if($event.RecordId -lt $AfterRecordId){throw 'Sysmon event log continuity changed.'}
    Start-Sleep -Milliseconds 250
  }while($deadline.Elapsed.TotalSeconds -lt 15)
  throw 'No matching new Sysmon configuration event was observed.'
}

function Invoke-RideSysmonPinnedConfiguration {
  param([string]$ExecutablePath,[string]$ConfigurationPath,[string]$Sha256)
  # Keep the checked source open without write/delete sharing while Sysmon reads
  # it. This also prevents a source replacement between verification and use.
  $stream=[IO.File]::Open($ConfigurationPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  $sha=[Security.Cryptography.SHA256]::Create()
  try {
    if($stream.Length -lt 1 -or $stream.Length -gt 2097152 -or [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') -cne $Sha256){throw 'Retained Sysmon XML changed before use.'}
    Invoke-RideSysmonConfigurationCommand $ExecutablePath $ConfigurationPath
  }finally{$sha.Dispose();$stream.Dispose()}
}

function Set-RideSysmonConfiguration {
  <#
  .SYNOPSIS
    Apply pinned XML after capturing a verified prior XML source.
  .PARAMETER ConfigurationPath
    Selected local schema 4.91 XML source.
  .PARAMETER ConfigurationSha256
    Reviewed SHA-256 of the selected source.
  .PARAMETER PriorConfigurationPath
    Restorable original XML matching the latest Sysmon configuration event.
  .PARAMETER PriorConfigurationSha256
    Reviewed SHA-256 of that prior source.
  .PARAMETER ExecutablePath
    Existing Microsoft-signed Sysmon64 service executable.
  .PARAMETER ExpectedExecutableSha256
    Explicit pinned executable digest.
  .PARAMETER ExpectedSysmonVersion
    Exact installed candidate version, starting with 15.21.
  .PARAMETER ExpectedComputerName
    Exact target computer name.
  .PARAMETER ExpectedBuild
    Exact Windows build.
  .PARAMETER ExpectedEditionId
    Exact Windows edition.
  .PARAMETER StateDirectory
    Existing local machine recovery directory.
  .PARAMETER AllowCandidate
    Fresh per-invocation opt-in; never bypasses source or recovery checks.
  .EXAMPLE
    Get-Help Set-RideSysmonConfiguration -Full
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Applied or AlreadyDesired result without XML content.
  .NOTES
    Preview creates no files and invokes no Sysmon process. No automatic install.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$ConfigurationPath,[Parameter(Mandatory)][string]$ConfigurationSha256,
    [Parameter(Mandatory)][string]$PriorConfigurationPath,[Parameter(Mandatory)][string]$PriorConfigurationSha256,
    [Parameter(Mandatory)][string]$ExecutablePath,[Parameter(Mandatory)][string]$ExpectedExecutableSha256,
    [Parameter(Mandatory)][string]$ExpectedSysmonVersion,[Parameter(Mandatory)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][string]$ExpectedBuild,[Parameter(Mandatory)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][string]$StateDirectory,[switch]$AllowCandidate)
  $context=Get-RideSysmonConfigurationContext $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion
  Assert-RideSysmonConfigurationContext $context $null (-not $WhatIfPreference)
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Selected Sysmon target differs.'}
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Sysmon configuration native acceptance is pending; use -AllowCandidate.'}
  Assert-RideSysmonStateDirectory $StateDirectory
  $desired=Read-RideSysmonSource $ConfigurationPath $ConfigurationSha256;$prior=Read-RideSysmonSource $PriorConfigurationPath $PriorConfigurationSha256
  $before=Get-RideSysmonConfigurationEvent
  if($before.Sha256 -ceq $desired.Sha256){return [pscustomobject]@{SchemaVersion=1;Status='AlreadyDesired';RunId=$null}}
  if($before.Sha256 -cne $prior.Sha256){throw 'Prior XML does not match the latest Sysmon configuration event; no recoverable source is established.'}
  $id=[guid]::NewGuid().ToString('N')
  $intent=[pscustomobject]@{SchemaVersion=1;Kind='SysmonConfiguration';RunId=$id;Part='intent.json';Context=$context;BeforeEvent=$before;BeforeSha256=$prior.Sha256;AfterSha256=$desired.Sha256}
  if($PSCmdlet.ShouldProcess($context.ComputerName,'Apply explicit Sysmon XML after private prior-source capture')){
    $stage='Capture'
    try {
      Save-RideSysmonPrivateBytes (Get-RideSysmonRunPath $StateDirectory $id before.xml) $prior.Bytes
      Save-RideSysmonPrivateBytes (Get-RideSysmonRunPath $StateDirectory $id after.xml) $desired.Bytes
      Save-RideSysmonRecord $StateDirectory $id intent.json $intent
      $stage='Preflight'
      Assert-RideSysmonConfigurationContext (Get-RideSysmonConfigurationContext $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion) $context $true
      $current=Get-RideSysmonConfigurationEvent
      if($current.RecordId -ne $before.RecordId -or $current.Sha256 -cne $before.Sha256){throw 'Sysmon configuration changed during preparation.'}
      $appliedPath=Get-RideSysmonRunPath $StateDirectory $id after.xml
      $stage='Apply'
      Invoke-RideSysmonPinnedConfiguration $context.ExecutablePath $appliedPath $desired.Sha256
      $stage='Verify'
      $after=Wait-RideSysmonConfigurationEvent $before.RecordId $desired.Sha256 $appliedPath
      Assert-RideSysmonConfigurationContext (Get-RideSysmonConfigurationContext $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion) $context $true
      Save-RideSysmonRecord $StateDirectory $id applied.json ([pscustomobject]@{SchemaVersion=1;Kind='SysmonConfiguration';RunId=$id;Part='applied.json';AfterEvent=$after})
      [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$id;NativeAcceptancePassed=$false}
    }catch{throw "Sysmon configuration did not complete. Run ID: $id. Stage: $stage. Retain private source/state; inspect service and configuration evidence before recovery."}
  }
}

function Restore-RideSysmonConfigurationRun {
  <#
  .SYNOPSIS
    Restore captured prior XML for a completed, unchanged configuration run.
  .PARAMETER RunId
    Completed source-bound Sysmon configuration run.
  .PARAMETER StateDirectory
    Existing private machine-state directory containing original XML and records.
  .PARAMETER AllowCandidate
    Fresh explicit opt-in for candidate recovery.
  .EXAMPLE
    Restore-RideSysmonConfigurationRun -RunId '<32-hex-run>' -StateDirectory C:\RIDE\State -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Restored or AlreadyRestored result.
  .NOTES
    Restores XML configuration only; existing events/archived files are retained.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$StateDirectory,[switch]$AllowCandidate)
  Assert-RideSysmonStateDirectory $StateDirectory
  $intent=Read-RideSysmonRecord $StateDirectory $RunId intent.json;$applied=Read-RideSysmonRecord $StateDirectory $RunId applied.json
  $expected=$intent.Context
  $context=Get-RideSysmonConfigurationContext $expected.ExecutablePath $expected.ExecutableSha256 $expected.SysmonVersion
  Assert-RideSysmonConfigurationContext $context $expected (-not $WhatIfPreference)
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Sysmon recovery requires fresh -AllowCandidate.'}
  $priorPath=Get-RideSysmonRunPath $StateDirectory $RunId before.xml
  $bytes=Read-RidePrivateFileBytes -Path $priorPath -Scope Machine -MaximumBytes 2097152
  if((Get-RideSysmonHash $bytes) -cne $intent.BeforeSha256){throw 'Captured prior Sysmon XML differs.'}
  $null=Read-RideSysmonSource $priorPath $intent.BeforeSha256
  $current=Get-RideSysmonConfigurationEvent
  if($current.Sha256 -ceq $intent.BeforeSha256){return [pscustomobject]@{SchemaVersion=1;Status='AlreadyRestored';RunId=$RunId}}
  if($current.RecordId -ne $applied.AfterEvent.RecordId -or $current.Sha256 -cne $intent.AfterSha256 -or $current.ConfigurationPath -ine $applied.AfterEvent.ConfigurationPath){throw 'Sysmon recovery conflict: configuration event changed.'}
  if($PSCmdlet.ShouldProcess($context.ComputerName,'Restore captured prior Sysmon XML')){
    try {
      Assert-RideSysmonConfigurationContext (Get-RideSysmonConfigurationContext $expected.ExecutablePath $expected.ExecutableSha256 $expected.SysmonVersion) $expected $true
      $latest=Get-RideSysmonConfigurationEvent
      if($latest.RecordId -ne $current.RecordId -or $latest.Sha256 -cne $current.Sha256){throw 'Sysmon configuration changed during recovery preflight.'}
      Invoke-RideSysmonPinnedConfiguration $context.ExecutablePath $priorPath $intent.BeforeSha256
      $null=Wait-RideSysmonConfigurationEvent $current.RecordId $intent.BeforeSha256 $priorPath
      Assert-RideSysmonConfigurationContext (Get-RideSysmonConfigurationContext $expected.ExecutablePath $expected.ExecutableSha256 $expected.SysmonVersion) $expected $true
      [pscustomobject]@{SchemaVersion=1;Status='Restored';RunId=$RunId;NativeAcceptancePassed=$false}
    }catch{throw "Sysmon configuration recovery did not complete. Run ID: $RunId. Retain private source/state; no successful restore is claimed."}
  }
}

Register-ArgumentCompleter -CommandName Restore-RideSysmonConfigurationRun -ParameterName RunId -ScriptBlock {
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{if(-not $fakeBoundParameters.ContainsKey('StateDirectory')){return};Get-ChildItem -LiteralPath $fakeBoundParameters.StateDirectory -Filter '*.sysmon.applied.json' -File -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.sysmon\.applied\.json$'){$id=$Matches[1];if($id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($id,$id,'ParameterValue','Saved Sysmon configuration run')}}}}catch{}
}
Export-ModuleMember -Function Set-RideSysmonConfiguration,Restore-RideSysmonConfigurationRun
