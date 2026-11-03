<#
.SYNOPSIS
  Verify synthetic all-user WLAN lifecycle in an attested disposable Windows VM.
.DESCRIPTION
  Tests import, repeat, replacement, owned removal and saved-run recovery without
  connecting. Missing WLAN prerequisites return NotRun, never a passing result.
  Failures retain private run records and do not reset the VM or delete profiles.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7, Windows 11 x64.
  Prerequisites: Existing elevated Hyper-V guest, correlated guest markers, WLAN
  service/interface and an existing local evidence root. No UAC or service start.
  Recovery: Restore completed run IDs in reverse order after inspecting failures;
  incomplete intent requires inspection. Checkpoint cleanup is a separate fallback.
  Version: 0.1.2.
  Changelog: 0.1.2: Retain observed WLAN service state when prerequisites are unavailable.
  0.1.1: Add private interface-only observation for retained dispatch.
  0.1.0: Add synthetic native lifecycle and exact observed-order checks.
.LINK
  ../../docs/wireless-profile-inventory.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.WirelessProfile.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.WirelessLifecycle.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.WirelessNative.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.WirelessInventory.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop

function Get-RideWirelessAcceptanceEnvironment {
  $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try {$admin=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}finally{$identity.Dispose()}
  $service=Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
  [pscustomobject]@{ComputerName=[Environment]::MachineName;Manufacturer=$computer.Manufacturer;Model=$computer.Model;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;InstallationType=[string]$version.InstallationType;NativeProcess=[Environment]::Is64BitProcess;Architecture=$env:PROCESSOR_ARCHITECTURE;Administrator=$admin;WlanService=if($service){[string]$service.Status}else{'Absent'};GuestMarker=$env:RIDE_TEST_GUEST;IntegrationMarker=$env:RIDE_INTEGRATION_VM;RunMarker=$env:RIDE_TEST_RUN_ID}
}

function Get-RideWirelessAcceptanceRows {
  param([guid]$InterfaceId)
  Initialize-RideWirelessProfileNative
  @([Ride.WirelessProfileV1.Client]::List($InterfaceId)|ForEach-Object {[pscustomobject]@{Name=$_.Name;Flags=[uint32]$_.Flags;Position=[int]$_.Position}})
}

function Get-RideWirelessAcceptanceInterfaceRows {
  # The existing bounded provider reads interface/profile-list metadata. Discard
  # profile rows here; do not request content, keys, scan results or connection.
  & (Get-Module RIDE.WirelessInventory) {
    $rows=@(Get-RideWirelessNativeRows)
    $null=ConvertTo-RideWirelessRows $rows
    @($rows|ForEach-Object {[pscustomobject]@{Id=([guid]$_.Id).ToString('D');State=[uint32]$_.State}})
  }
}

function Get-RideWirelessAcceptanceInterfaces {
  # Internal read-only helper called after the retained remote target guard.
  $context=Get-RideWirelessAcceptanceEnvironment
  $result=[pscustomobject]@{SchemaVersion=1;Kind='WirelessInterfaceObservation';Status='NotRun';Reason='WlanServiceUnavailable';WlanService=[string]$context.WlanService;Interfaces=@();ProfileContentRead=$false;ConnectionAttempted=$false;NativeAcceptancePassed=$false}
  if($context.WlanService -cne 'Running'){return $result}
  try{$rows=@(Get-RideWirelessAcceptanceInterfaceRows)}catch{$result.Reason='WlanInterfaceUnavailable';return $result}
  if(-not $rows.Count){$result.Reason='NoWlanInterfaces';return $result}
  $result.Status='Available';$result.Reason=$null;$result.Interfaces=$rows
  $result
}

function Test-RideWirelessAcceptanceProfile {
  param([guid]$InterfaceId,[string]$Name,[string]$Ssid,[string]$SyntheticKey)
  $content=Get-RideWirelessAcceptanceContent $InterfaceId $Name
  if(-not $content.Present -or $content.Flags -ne 0){return $false}
  # Content stays inside this boundary. Results and assertions contain no XML/key.
  $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=262144
  $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($content.Xml),$settings)
  try {
    $doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
    $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('w','http://www.microsoft.com/networking/WLAN/profile/v1')
    $checks=@{
      '/w:WLANProfile/w:name'=$Name
      '/w:WLANProfile/w:SSIDConfig/w:SSID/w:hex'=[BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($Ssid)).Replace('-','')
      '/w:WLANProfile/w:connectionMode'='manual'
      '/w:WLANProfile/w:MSM/w:security/w:authEncryption/w:authentication'='WPA2PSK'
      '/w:WLANProfile/w:MSM/w:security/w:authEncryption/w:encryption'='AES'
      '/w:WLANProfile/w:MSM/w:security/w:sharedKey/w:protected'='false'
      '/w:WLANProfile/w:MSM/w:security/w:sharedKey/w:keyMaterial'=$SyntheticKey
    }
    foreach($path in $checks.Keys){
      $nodes=$doc.SelectNodes($path,$ns);if($nodes.Count -ne 1){return $false}
      $value=$nodes[0].InnerText
      if($path -ceq '/w:WLANProfile/w:SSIDConfig/w:SSID/w:hex'){$value=$value.ToUpperInvariant()}
      if($value -cne $checks[$path]){return $false}
    }
    return $true
  }finally{$reader.Dispose()}
}

function Get-RideWirelessAcceptanceContent {
  param([guid]$InterfaceId,[string]$Name)
  Initialize-RideWirelessProfileNative
  [Ride.WirelessProfileV1.Client]::Read($InterfaceId,$Name,$true)
}

function Save-RideWirelessAcceptanceReport {
  param([string]$Path,$Report)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes((($Report|ConvertTo-Json -Depth 8).Replace("`r`n","`n"))+"`n")
  $stream=New-RidePrivateFileStream -Path $Path
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}

function Assert-RideWirelessAcceptanceResult {
  param($Result,[string]$Status,[bool]$NeedsRunId=$false)
  if($null -eq $Result -or $Result.SchemaVersion -ne 1 -or $Result.Status -cne $Status -or ($NeedsRunId -and $Result.RunId -cnotmatch '^[a-f0-9]{32}$')){throw 'Lifecycle result did not satisfy the acceptance step.'}
}

function Invoke-RideWirelessAcceptance {
  <#
  .SYNOPSIS
    Execute synthetic profile lifecycle with independent native readback.
  .PARAMETER RunId
    Correlated 32-hex guest request ID; must match RIDE_TEST_RUN_ID.
  .PARAMETER InterfaceId
    Explicit nonempty WLAN interface GUID observed on this disposable target.
  .PARAMETER ExpectedComputerName
    Independently identified guest name.
  .PARAMETER ExpectedBuild
    Exact Windows build number.
  .PARAMETER ExpectedEditionId
    Exact Windows edition identity.
  .PARAMETER EvidenceRoot
    Existing local directory. A new RunId subdirectory retains private state/report.
  .PARAMETER DisposableVm
    Required attestation, additional to the native guest/target checks.
  .EXAMPLE
    Invoke-RideWirelessAcceptance -RunId '<32-hex-request>' -InterfaceId '<guid>' -ExpectedComputerName '<guest>' -ExpectedBuild '26300' -ExpectedEditionId EnterpriseEval -EvidenceRoot C:\RIDE\WirelessAcceptance -DisposableVm -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 status report: Preview, NotRun, Passed or Failed. No XML or key material.
  .NOTES
    No connection request or checkpoint reset. Passed covers this synthetic scope
    only and cannot establish general DACL drift recovery or network connectivity.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidatePattern('(?-i)^[a-f0-9]{32}$')][string]$RunId,
    [Parameter(Mandatory)][guid]$InterfaceId,[Parameter(Mandatory)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][string]$ExpectedBuild,[Parameter(Mandatory)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][string]$EvidenceRoot,[switch]$DisposableVm)
  $context=Get-RideWirelessAcceptanceEnvironment
  if(-not $DisposableVm -or $context.GuestMarker -cne '1' -or $context.IntegrationMarker -cne '1' -or $context.RunMarker -cne $RunId -or $context.Manufacturer -cne 'Microsoft Corporation' -or $context.Model -cne 'Virtual Machine'){throw 'Wireless acceptance requires a correlated disposable Hyper-V guest; workstation mutation is refused.'}
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId -or $context.InstallationType -cne 'Client' -or $context.Build -cnotmatch '^\d{5,8}$' -or [int]$context.Build -lt 22000 -or -not $context.NativeProcess -or $context.Architecture -cne 'AMD64'){throw 'Wireless acceptance target differs from the expected Windows 11 x64 client.'}
  if($InterfaceId -eq [guid]::Empty){throw 'Select an explicit nonempty WLAN interface GUID.'}
  $root=[IO.Path]::GetFullPath($EvidenceRoot)
  if($root -notmatch '^[A-Za-z]:\\' -or $root.Substring(2).Contains(':') -or -not [IO.Directory]::Exists($root) -or [IO.DriveInfo]::new([IO.Path]::GetPathRoot($root)).DriveType -eq [IO.DriveType]::Network){throw 'Acceptance evidence requires an existing local directory without alternate streams.'}
  for($node=[IO.DirectoryInfo]::new($root);$null -ne $node;$node=$node.Parent){if($node.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Acceptance evidence ancestors must not be reparse points.'}}
  $directory=Join-Path $root $RunId
  if(Test-Path -LiteralPath $directory){throw 'Acceptance evidence already exists; retain it and use a new request ID.'}
  $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WirelessLifecycleAcceptance';RunId=$RunId;RecordedAtUtc=[DateTime]::UtcNow.ToString('o');Status='NotRun';Reason=$null;Stage='Preflight';NativeAcceptancePassed=$false;ConnectionAttempted=$false;RecoveryRequired=$false;ComputerName=$context.ComputerName;Build=$context.Build;EditionId=$context.EditionId;InterfaceId=$InterfaceId.ToString('D');Checks=@();LifecycleRuns=@();StateRunIds=@();EvidenceDirectory=$null;RecoveryLimits='Synthetic all-user XML/order and known creation permissions only; no general DACL drift or network connection claim.'}
  if(-not $context.Administrator -and -not $WhatIfPreference){$report.Reason='ExistingElevationRequired';return $report}
  if($context.WlanService -cne 'Running'){$report.Reason='WlanServiceUnavailable';return $report}
  try{$before=@(Get-RideWirelessAcceptanceRows $InterfaceId)}catch{$report.Reason='WlanInterfaceUnavailable';return $report}
  $fixture=Import-PowerShellDataFile (Join-Path $PSScriptRoot '../fixtures/wireless-profile.synthetic.psd1')
  $name=$fixture.ProfileName+' '+$RunId.Substring(0,8)
  if(@($before|Where-Object Name -CEQ $name).Count){$report.Reason='SyntheticProfileCollision';return $report}
  if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Run synthetic all-user WLAN import/repeat/replace/remove/restore; retain private evidence')){$report.Status='Preview';$report.Reason='MutationNotRequested';return $report}
  $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
  $report.EvidenceDirectory=$directory
  $state=Join-Path $directory 'state';$null=New-Item -ItemType Directory -Path $state -ErrorAction Stop
  $checks=[Collections.Generic.List[string]]::new();$runs=[Collections.Generic.List[object]]::new()
  $key=$null
  try {
    $report.Stage='Generate'
    $key=ConvertTo-SecureString $fixture.SyntheticKey -AsPlainText -Force
    $profilePath=Join-Path $directory 'synthetic.xml'
    $null=New-RideWirelessProfileFile -ProfileName $name -Ssid $fixture.Ssid -Security WPA2Personal -Key $key -ConnectionMode manual -OutputPath $profilePath
    $replacementPath=Join-Path $directory 'replacement.xml'
    $replacementSsid='RIDE-SYNTHETIC-REPLACEMENT'
    $null=New-RideWirelessProfileFile -ProfileName $name -Ssid $replacementSsid -Security WPA2Personal -Key $key -ConnectionMode manual -OutputPath $replacementPath
    $selection=@{ProfilePath=$profilePath;InterfaceId=$InterfaceId;StateDirectory=$state;ExpectedComputerName=$ExpectedComputerName;ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;AllowCandidate=$true;Confirm=$false}
    $report.Stage='Preview'
    $null=Install-RideWirelessProfile @selection -WhatIf
    if(@(Get-ChildItem -LiteralPath $state -File).Count -ne 0 -or (ConvertTo-Json -InputObject @($before) -Compress) -cne (ConvertTo-Json -InputObject @(Get-RideWirelessAcceptanceRows $InterfaceId) -Compress)){throw 'Preview changed state.'}
    $checks.Add('PreviewNoChanges')
    $report.Stage='Import'
    $installed=Install-RideWirelessProfile @selection
    Assert-RideWirelessAcceptanceResult $installed Applied $true
    $runs.Add([pscustomobject]@{Action='Import';RunId=$installed.RunId;Restored=$false})
    if(-not (Test-RideWirelessAcceptanceProfile $InterfaceId $name $fixture.Ssid $fixture.SyntheticKey)){throw 'Independent import verification failed.'}
    $checks.Add('ImportAndNativeReadback')
    $report.Stage='Repeat'
    $filesBefore=@(Get-ChildItem -LiteralPath $state -File).Count
    Assert-RideWirelessAcceptanceResult (Install-RideWirelessProfile @selection) AlreadyDesired
    if(@(Get-ChildItem -LiteralPath $state -File).Count -ne $filesBefore){throw 'Repeat created another state record.'}
    $checks.Add('RepeatWithoutNewRun')
    $report.Stage='Replace'
    $selection.ProfilePath=$replacementPath
    $replacement=Install-RideWirelessProfile @selection -ReplaceExisting
    Assert-RideWirelessAcceptanceResult $replacement Applied $true
    $runs.Add([pscustomobject]@{Action='Replace';RunId=$replacement.RunId;Restored=$false})
    if(-not (Test-RideWirelessAcceptanceProfile $InterfaceId $name $replacementSsid $fixture.SyntheticKey)){throw 'Independent replacement verification failed.'}
    $checks.Add('ReplacementAndNativeReadback')
    $report.Stage='RestoreReplacement'
    Assert-RideWirelessAcceptanceResult (Restore-RideWirelessProfileRun -RunId $replacement.RunId -StateDirectory $state -AllowCandidate -Confirm:$false) Restored
    if(-not (Test-RideWirelessAcceptanceProfile $InterfaceId $name $fixture.Ssid $fixture.SyntheticKey)){throw 'Independent replacement recovery verification failed.'}
    $runs[1].Restored=$true;$checks.Add('PriorSyntheticProfileRestored')
    $report.Stage='Remove'
    $removed=Remove-RideWirelessProfile -OwnerRunId $installed.RunId -StateDirectory $state -AllowCandidate -Confirm:$false
    Assert-RideWirelessAcceptanceResult $removed Applied $true
    $runs.Add([pscustomobject]@{Action='Remove';RunId=$removed.RunId;Restored=$false})
    if(@(Get-RideWirelessAcceptanceRows $InterfaceId|Where-Object Name -CEQ $name).Count){throw 'Owned profile remained.'}
    $checks.Add('OwnedRemoval')
    $report.Stage='RestoreRemoval'
    Assert-RideWirelessAcceptanceResult (Restore-RideWirelessProfileRun -RunId $removed.RunId -StateDirectory $state -AllowCandidate -Confirm:$false) Restored
    if(-not (Test-RideWirelessAcceptanceProfile $InterfaceId $name $fixture.Ssid $fixture.SyntheticKey)){throw 'Independent removal recovery verification failed.'}
    $runs[2].Restored=$true;$checks.Add('RemovedProfileRestored')
    $report.Stage='RestoreInitial'
    Assert-RideWirelessAcceptanceResult (Restore-RideWirelessProfileRun -RunId $installed.RunId -StateDirectory $state -AllowCandidate -Confirm:$false) Restored
    $after=@(Get-RideWirelessAcceptanceRows $InterfaceId)
    if((ConvertTo-Json -InputObject $before -Compress) -cne (ConvertTo-Json -InputObject $after -Compress)){throw 'Initial profile membership/flags/order were not restored.'}
    $runs[0].Restored=$true;$checks.Add('InitialAbsenceAndOrderRestored')
    Assert-RideWirelessAcceptanceResult (Restore-RideWirelessProfileRun -RunId $installed.RunId -StateDirectory $state -AllowCandidate -Confirm:$false) AlreadyRestored
    $checks.Add('RepeatedRestoreNoChange')
    $report.Stage='Complete';$report.Status='Passed';$report.NativeAcceptancePassed=$true
  }catch{
    $report.Status='Failed';$report.Reason='AcceptanceStepFailed';$report.RecoveryRequired=$true
    # Native exceptions may include sensitive provider diagnostics. The retained
    # stage and private state identify the boundary without echoing the exception.
  }finally{if($key){$key.Dispose()}}
  $report.Checks=@($checks.ToArray());$report.LifecycleRuns=@($runs.ToArray())
  $report.StateRunIds=@(Get-ChildItem -LiteralPath $state -Filter '*.intent.dat' -File|Select-Object -First 256|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.intent\.dat$'){$Matches[1]}})
  Save-RideWirelessAcceptanceReport -Path (Join-Path $directory 'result.json') -Report $report
  $report
}

Export-ModuleMember -Function Invoke-RideWirelessAcceptance
