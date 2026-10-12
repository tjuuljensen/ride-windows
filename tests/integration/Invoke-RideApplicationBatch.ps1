<#
.SYNOPSIS
  Validate one application migration batch in a disposable Windows guest.
.DESCRIPTION
  Exercises previews, install/repeat/remove and saved-run recovery. Portable
  scenarios also preserve user files and recover an explicit uninstall.
.PARAMETER Batch
  Installed applications (1) or portable applications (2).
.PARAMETER Version
  Print the script version without running scenarios.
.PARAMETER UnelevatedChild
  Internal disposable-guest worker for packages requiring a limited token.
.PARAMETER ExpectedUserSid
  Internal worker identity correlation; must match the temporary standard user.
.PARAMETER ExpectedLocalAppData
  Internal worker profile correlation; must match the temporary user's profile.
.EXAMPLE
  .\Invoke-RideApplicationBatch.ps1 -Batch 2
.INPUTS
  None.
.OUTPUTS
  Scenario results; correlated evidence remains in the guest result directory.
.NOTES
  Compatibility: Windows PowerShell 5.1 on disposable Windows 11/Server 2025.
  Prerequisites: Elevated guest, RIDE_INTEGRATION_VM=1 and the VM test runner.
  Recovery: Saved-run restoration and host clean-checkpoint recovery.
  Owner: RIDE-Windows maintainers. Version: 0.4.4.
  Changelog: 0.4.4: Grant and remove batch-logon rights for the temporary guest account only.
    0.4.3: Start the registered task object and collect focused guest event history.
    0.4.2: Retain limited-worker task startup diagnostics before cleanup.
    0.4.1: Use a temporary standard account and fail promptly on worker startup.
    0.4.0: Validate Thunderbird in a limited guest context.
    0.3.0: Check WinSCP portable signatures and session preservation.
    0.2.0: Check Chrome/Signal profile preservation and removal recovery.
    0.1.0: Add two package-only migration suites.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([ValidateSet(1,2)][int] $Batch=1,[switch] $Version,[switch] $UnelevatedChild,[string] $ExpectedUserSid,[string] $ExpectedLocalAppData)
$script:ScriptVersion='0.4.4'
if($Version){$script:ScriptVersion;return}
$ErrorActionPreference='Stop'
if($env:RIDE_INTEGRATION_VM -ne '1'){throw 'Run application scenarios only through the disposable-VM runner.'}
$workerIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
$workerElevated=([Security.Principal.WindowsPrincipal]::new($workerIdentity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($UnelevatedChild -and ($workerElevated -or $workerIdentity.User.Value -cne $ExpectedUserSid)){throw 'Limited worker identity or elevation does not match the authorized guest context.'}
if($UnelevatedChild -and ([Environment]::GetFolderPath('LocalApplicationData') -ine $ExpectedLocalAppData)){throw 'Limited worker profile does not match the authorized guest user.'}
if(-not $UnelevatedChild -and ($ExpectedUserSid -or $ExpectedLocalAppData)){throw 'Identity correlation requires the internal limited worker.'}
if(-not $PSCmdlet.ShouldProcess('Disposable guest',"Run applications batch $Batch")){return}
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PackageSelection.psm1') -Force
$target=Get-RidePlatform
if($target -notin @('Windows 11','Windows Server 2025')){throw "Application acceptance requires the declared Windows 11/Server 2025 guests; found $target."}
$guestOs=Get-CimInstance Win32_OperatingSystem
$installationType=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType -ErrorAction Stop).InstallationType
$catalog=Get-RideCatalog
$scenarios=@()
foreach($package in $catalog.Operations | Where-Object Kind -eq 'Package'){
  $names=if($package.Variants){@($package.Variants.Keys)}else{@('installed')}
  foreach($variant in $names){
    $selected=Resolve-RidePackageSelection -Operation $package -Variant $variant
    if($selected.MigrationBatch -eq "ApplicationsBatch$Batch"){$scenarios+=@{Id=$package.Id;Variant=$variant;Selected=$selected}}
  }
}
if(-not $scenarios.Count){throw 'No application scenarios were selected.'}
$results=New-Object System.Collections.Generic.List[object]
$evidenceFile=if($UnelevatedChild){"applications-batch$Batch-user.json"}else{"applications-batch$Batch.json"}
if($UnelevatedChild){
  # The limited user writes acquisition evidence in its own output directory.
  # The elevated coordinator merges it after the worker has stopped.
  & (Get-Module -All RIDE-Packages | Select-Object -First 1) {param($path) $script:PSDefaultParameterValues=@{'Save-RidePackageArtifact:ObservationPath'=$path}} (Join-Path $env:RIDE_TEST_EVIDENCE_PATH 'application-user-observations.json')
}
if(-not $UnelevatedChild -and @($scenarios | Where-Object {$_.Selected.RequiresUnelevatedUser}).Count){
  if(-not $workerElevated -or -not $env:RIDE_TEST_EVIDENCE_PATH){throw 'The limited-worker coordinator requires the elevated disposable guest and an evidence directory.'}
  $taskName='RIDE-ApplicationUser-'+[guid]::NewGuid().ToString('N')
  $accountName='RIDE-App-'+[guid]::NewGuid().ToString('N').Substring(0,8)
  $testUser=$null;$registered=$false;$workerRoot=$null;$profilePath=$null;$batchRightGranted=$false
  try{
    # Test-only account: no administrator membership and no change to UAC policy.
    $temporaryPassword='Aa1!'+[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N')
    $password=ConvertTo-SecureString $temporaryPassword -AsPlainText -Force
    $testUser=New-LocalUser -Name $accountName -Password $password -AccountNeverExpires -PasswordNeverExpires
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $testUser
    if(@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object {$_.SID -eq $testUser.SID}).Count){throw 'Disposable test account unexpectedly belongs to Administrators.'}
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
namespace RideTest {
  public static class UserProfile {
    [DllImport("userenv.dll", CharSet=CharSet.Unicode)]
    public static extern int CreateProfile(string userSid, string userName, StringBuilder profilePath, uint capacity);
    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes {
      public uint Length;
      public IntPtr RootDirectory, ObjectName;
      public uint Attributes;
      public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct LsaUnicodeString {
      public ushort Length, MaximumLength;
      public IntPtr Buffer;
    }
    [DllImport("advapi32.dll")]
    private static extern uint LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes attributes, uint access, out IntPtr handle);
    [DllImport("advapi32.dll")]
    private static extern uint LsaAddAccountRights(IntPtr handle, IntPtr sid, LsaUnicodeString[] rights, uint count);
    [DllImport("advapi32.dll")]
    private static extern uint LsaRemoveAccountRights(IntPtr handle, IntPtr sid, [MarshalAs(UnmanagedType.U1)] bool allRights, LsaUnicodeString[] rights, uint count);
    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr handle);
    [DllImport("advapi32.dll")]
    private static extern uint LsaNtStatusToWinError(uint status);
    private static void Check(uint status) {
      if(status != 0) throw new System.ComponentModel.Win32Exception((int)LsaNtStatusToWinError(status));
    }
    // Only the newly created disposable account is passed by the coordinator.
    public static void SetBatchLogonRight(string userSid, bool grant) {
      var sid = new System.Security.Principal.SecurityIdentifier(userSid);
      byte[] bytes = new byte[sid.BinaryLength];
      sid.GetBinaryForm(bytes, 0);
      IntPtr sidBuffer = Marshal.AllocHGlobal(bytes.Length);
      IntPtr rightBuffer = Marshal.StringToHGlobalUni("SeBatchLogonRight");
      IntPtr policy = IntPtr.Zero;
      try {
        Marshal.Copy(bytes, 0, sidBuffer, bytes.Length);
        var attributes = new LsaObjectAttributes();
        attributes.Length = (uint)Marshal.SizeOf(typeof(LsaObjectAttributes));
        Check(LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x810, out policy));
        var right = new LsaUnicodeString {Length=34, MaximumLength=36, Buffer=rightBuffer};
        var rights = new LsaUnicodeString[] {right};
        if(grant) Check(LsaAddAccountRights(policy, sidBuffer, rights, 1));
        else Check(LsaRemoveAccountRights(policy, sidBuffer, false, rights, 1));
      } finally {
        if(policy != IntPtr.Zero) LsaClose(policy);
        Marshal.FreeHGlobal(rightBuffer);
        Marshal.FreeHGlobal(sidBuffer);
      }
    }
  }
}
'@
    [RideTest.UserProfile]::SetBatchLogonRight($testUser.SID.Value,$true)
    $batchRightGranted=$true
    $profileBuffer=New-Object Text.StringBuilder 260
    $profileResult=[RideTest.UserProfile]::CreateProfile($testUser.SID.Value,$accountName,$profileBuffer,260)
    if($profileResult -ne 0){[Runtime.InteropServices.Marshal]::ThrowExceptionForHR($profileResult);throw 'Disposable profile creation failed.'}
    $profilePath=$profileBuffer.ToString()
    $localAppDataPath=Join-Path $profilePath 'AppData/Local'
    $workerRoot=Join-Path $localAppDataPath ('RIDE/TestWorkers/'+$taskName)
    if(Test-Path -LiteralPath $workerRoot){throw 'Limited-worker output directory already exists.'}
    $null=New-Item -ItemType Directory -Path $workerRoot -Force
    $scriptPath=$PSCommandPath.Replace("'","''")
    $evidencePath=$workerRoot.Replace("'","''")
    $localAppData=$localAppDataPath.Replace("'","''")
    $command="try{[IO.File]::WriteAllText('$evidencePath/application-user-bootstrap.log', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value);`$env:RIDE_INTEGRATION_VM='1';`$env:RIDE_TEST_EVIDENCE_PATH='$evidencePath';`$env:RIDE_TEST_RUN_ID='$($env:RIDE_TEST_RUN_ID)'; & '$scriptPath' -Batch $Batch -UnelevatedChild -ExpectedUserSid '$($testUser.SID.Value)' -ExpectedLocalAppData '$localAppData' *> '$evidencePath/application-user-worker.log';exit 0}catch{[IO.File]::AppendAllText('$evidencePath/application-user-worker.log',(`$_ | Out-String));exit 1}"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action=New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded" -WorkingDirectory (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $childPath=Join-Path $workerRoot "applications-batch$Batch-user.json"
    # Enable diagnostic history only inside this disposable guest; checkpoint
    # recovery restores its prior logging configuration.
    & wevtutil.exe sl Microsoft-Windows-TaskScheduler/Operational /e:true
    if($LASTEXITCODE -ne 0){throw 'Could not enable disposable-guest task diagnostic history.'}
    $registeredTask=Register-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -Action $action -User ($env:COMPUTERNAME+'\'+$accountName) -Password $temporaryPassword -RunLevel Limited -Settings $settings
    $temporaryPassword=$null
    $registered=$true
    Start-ScheduledTask -InputObject $registeredTask
    $startupDeadline=[datetime]::UtcNow.AddSeconds(60)
    $deadline=[datetime]::UtcNow.AddMinutes(21)
    do{
      Start-Sleep -Seconds 2
      $info=Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\RIDE\'
      $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\'
      if($info.LastTaskResult -gt 65535 -and $info.LastTaskResult -notin @(267009,267011)){throw "Limited worker could not start: $($info.LastTaskResult)."}
      if($info.LastRunTime.Year -le 2000 -and [datetime]::UtcNow -gt $startupDeadline){throw 'Limited worker did not start within 60 seconds; inspect task logon rights and run conditions.'}
      # The task state and last-result updates are not atomic.
      if($info.LastRunTime.Year -gt 2000 -and $task.State -notin @('Running','Queued') -and $info.LastTaskResult -ne 267009){break}
    }while([datetime]::UtcNow -lt $deadline)
    if($task.State -eq 'Running' -or $info.LastTaskResult -eq 267009){Stop-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\';throw 'Limited application worker timed out.'}
    if($info.LastTaskResult -ne 0 -or -not(Test-Path -LiteralPath $childPath)){throw "Limited application worker failed: $($info.LastTaskResult); see application-user-worker.log."}
    foreach($row in @(Get-Content -LiteralPath $childPath -Raw | ConvertFrom-Json)){
      if($row.ExecutionSid -cne $testUser.SID.Value -or $row.Elevated -ne $false -or $row.LocalAppData -ine $localAppDataPath){throw 'Limited application evidence identity mismatch.'}
      $row | Add-Member -NotePropertyName TestUserSid -NotePropertyValue $testUser.SID.Value
      $results.Add($row)
    }
  }finally{
    try{
      if($registered){
        # Capture only this disposable task; do not export account credentials.
        try{
          $diagnosticTask=Get-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\'
          $diagnosticInfo=$diagnosticTask | Get-ScheduledTaskInfo
          [ordered]@{TaskName=$taskName;State=[string]$diagnosticTask.State;LastTaskResult=$diagnosticInfo.LastTaskResult;LastRunTime=$diagnosticInfo.LastRunTime;Principal=($diagnosticTask.Principal | Select-Object UserId,LogonType,RunLevel);Settings=($diagnosticTask.Settings | Select-Object AllowDemandStart,Enabled,DisallowStartIfOnBatteries,RunOnlyIfIdle,RunOnlyIfNetworkAvailable,UseUnifiedSchedulingEngine)} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $env:RIDE_TEST_EVIDENCE_PATH 'application-user-task.json') -Encoding UTF8
          $taskEvents=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';StartTime=[datetime]::Now.AddMinutes(-25)} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {$_.Message -like "*$taskName*"} | Select-Object TimeCreated,Id,LevelDisplayName,Message)
          ConvertTo-Json -InputObject $taskEvents -Depth 4 | Set-Content -LiteralPath (Join-Path $env:RIDE_TEST_EVIDENCE_PATH 'application-user-task-events.json') -Encoding UTF8
        }catch{Write-Warning "Limited-worker diagnostic collection failed: $($_.Exception.Message)"}
        if((Get-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\').State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\'}
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -Confirm:$false -ErrorAction Stop
      }
      if($workerRoot){
        foreach($name in @('application-user-bootstrap.log','application-user-worker.log','application-user-observations.json',"applications-batch$Batch-user.json")){
          $source=Join-Path $workerRoot $name
          if(Test-Path -LiteralPath $source){Copy-Item -LiteralPath $source -Destination (Join-Path $env:RIDE_TEST_EVIDENCE_PATH $name)}
        }
      }
      if($profilePath){
        $state=Join-Path $profilePath 'AppData/Local/RIDE/State'
        if(Test-Path -LiteralPath $state){
          $destination=Join-Path $env:RIDE_TEST_EVIDENCE_PATH 'state/ThunderbirdUser'
          $null=New-Item -ItemType Directory -Path $destination -Force
          Get-ChildItem -LiteralPath $state -Force | Where-Object Name -NotIn @('Cache','Artifacts') | ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse}
        }
      }
    }finally{
      if($testUser){
        try{if($batchRightGranted){[RideTest.UserProfile]::SetBatchLogonRight($testUser.SID.Value,$false)}}
        finally{Remove-LocalUser -SID $testUser.SID -ErrorAction Stop}
      }
    }
  }
  & (Join-Path $PSScriptRoot '../../tools/Import-RideArtifactObservations.ps1') -Path (Join-Path $workerRoot 'application-user-observations.json') -LibraryPath (Join-Path $PSScriptRoot '../../catalog/artifact-observations.json') -Confirm:$false | Out-Null
  foreach($row in $results){
    $row | Add-Member -NotePropertyName LimitedWorkerCleanup -NotePropertyValue $true
    $row | Add-Member -NotePropertyName TestAccountCleanup -NotePropertyValue $true
    $row | Add-Member -NotePropertyName BatchLogonRightCleanup -NotePropertyValue $true
  }
}
$scenarios=@($scenarios | Where-Object {[bool]$_.Selected.RequiresUnelevatedUser -eq [bool]$UnelevatedChild})
function Get-SavedRunId($Output){
  $id=($Output | Where-Object {$_ -is [string] -and $_ -match '^Run ID: '} | Select-Object -Last 1)-replace '^Run ID: ',''
  if(-not $id){throw 'Scenario did not return a saved run.'};$id
}
# Test-only support metadata lives in memory inside this guarded guest. It is
# never written back to the production catalog or used as acceptance evidence.
$testCatalog=Get-RideCatalog
foreach($package in $testCatalog.Operations | Where-Object Kind -eq 'Package'){
  if($package.MigrationBatch -like 'ApplicationsBatch*'){
    $package.SupportedTargets=@($package.SupportedTargets)+@($target) | Select-Object -Unique
    $package.PendingAcceptance=$false
  }
  foreach($variant in $package.Variants.Values){
    if($variant.MigrationBatch -like 'ApplicationsBatch*'){
      $variant.SupportedTargets=@($variant.SupportedTargets)+@($target) | Select-Object -Unique
      $variant.PendingAcceptance=$false
    }
  }
}
& (Get-Module RIDE.Engine) {param($candidateCatalog) $script:RideLibraryContext=@{Catalog=$candidateCatalog}} $testCatalog
foreach($scenario in $scenarios){
  $package=Resolve-RidePackageSelection (Get-RideOperation $scenario.Id) -Variant $scenario.Variant
  $scenarioResult=[ordered]@{Id=$scenario.Id;Variant=$scenario.Variant;Target=$target;OS=$guestOs.Caption;Build=$guestOs.BuildNumber;InstallationType=$installationType;Scope=$package.Scope;Provider=$package.DownloadProvider;Applicability='Applicable to deployment lifecycle';Status='Failed';Version=$null;Error=$null;Recovery=$false;ProfilePreservation=$null;RemovalRecoveryVersion=$null;RecoveryMode=if($package.InstallerType -eq 'Portable'){'Exact owned-file recovery'}else{'Compensating presence recovery; previous-version recovery unavailable'}}
  $scenarioResult.ExecutionSid=$workerIdentity.User.Value
  $scenarioResult.Elevated=$workerElevated
  $scenarioResult.LocalAppData=[Environment]::GetFolderPath('LocalApplicationData')
  if($package.RequiresDesktopExperience -and $target -like 'Windows Server*' -and $installationType -ne 'Server'){
    $scenarioResult.Applicability='Unavailable: requires Desktop Experience';$scenarioResult.Status='NotApplicable';$scenarioResult.Recovery=$true
    $results.Add([pscustomobject]$scenarioResult);continue
  }
  try{
    $plan=@(Get-RideSingleOperationPlan -Id $scenario.Id -Action Install -Variant $scenario.Variant)
    $before=Get-RideCurrentState $plan[0].Operation
    if($before.Present){throw 'Clean application test guest unexpectedly contains this edition.'}
    $profileFixture=$null
    $sessionFixture=$null
    $sessionFile=$null
    if($scenario.Id -in @('package.chrome','package.signal','package.thunderbird')){
      $profileRoot=if($scenario.Id -eq 'package.chrome'){Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Google/Chrome/User Data'}elseif($scenario.Id -eq 'package.thunderbird'){Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Thunderbird'}else{Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Signal'}
      New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
      $profileFixture=Join-Path $profileRoot ('ride-preservation-'+[guid]::NewGuid().ToString('N')+'.txt')
      [IO.File]::WriteAllText($profileFixture,'Keep existing profile data.')
    }
    $null=Invoke-RidePlan $plan -WhatIf -Confirm:$false
    if((Get-RideCurrentState $plan[0].Operation).Present){throw 'Install preview changed package state.'}
    $runId=Get-SavedRunId @(Invoke-RidePlan $plan -Confirm:$false)
    $installed=Get-RideCurrentState $plan[0].Operation
    if(-not (Test-RideDesiredState $plan[0].Operation Present)){throw 'Installation did not establish the desired state.'}
    $scenarioResult.Version=$installed.DisplayVersion
    if($scenario.Id -eq 'package.thunderbird'){
      if($installed.InstallLocation -ine $package.InstallDirectory -or $installed.DisplayName -notmatch '\(x64 en-GB\)$'){throw 'Thunderbird registration does not match the saved user selection.'}
      $scenarioResult.InstallDirectory=$installed.InstallLocation
      $channelPath=Join-Path $installed.InstallLocation 'defaults/pref/channel-prefs.js'
      if(-not(Test-Path -LiteralPath $channelPath) -or (Get-Content -LiteralPath $channelPath -Raw) -notmatch 'pref\("app.update.channel",\s*"release"\)'){throw 'Installed Thunderbird is not the Release channel.'}
      $scenarioResult.Channel='release'
    }
    if($scenario.Id -eq 'package.winscp'){
      $members=@($installed.Manifest.Files)
      if($members.Count -ne 4 -or @($members | Where-Object { $_.RelativePath -notin @('WinSCP.exe','WinSCP.com','license.txt','readme.txt') }).Count){throw 'Unexpected WinSCP owned-file inventory.'}
      if(@($members | Where-Object {$_.RelativePath -in @('WinSCP.exe','WinSCP.com') -and ($_.AuthenticodeStatus -ne 'Valid' -or -not $_.SignerThumbprint)}).Count){throw 'WinSCP executable signature evidence is incomplete.'}
      $scenarioResult.FileEvidence=$members
    }
    $repeat=@(Invoke-RidePlan $plan -Confirm:$false)
    if('No changes were needed; no state record was created.' -notin $repeat){throw 'Repeat installation was not idempotent.'}
    $null=Restore-RideRun -RunId $runId -WhatIf -Confirm:$false
    if(-not (Test-RideDesiredState $plan[0].Operation Present)){throw 'Restore preview changed presence.'}
    if($package.InstallerType -eq 'Portable'){
      $userFile=Join-Path $package.InstallDirectory 'ride-user-preservation-fixture.txt'
      [IO.File]::WriteAllText($userFile,'Keep this user file.')
      if($scenario.Id -eq 'package.winscp'){
        $sessionFile=Join-Path $package.InstallDirectory 'WinSCP.ini'
        [IO.File]::WriteAllText($sessionFile,"[Sessions\RIDEFixture]`r`nHostName=example.invalid`r`n")
        $sessionFixture='HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions\RIDE-'+[guid]::NewGuid().ToString('N')
        $null=New-Item -Path $sessionFixture -Force
        $null=New-ItemProperty -LiteralPath $sessionFixture -Name HostName -Value 'example.invalid' -PropertyType String
      }
      $remove=@(Get-RideSingleOperationPlan -Id $scenario.Id -Action Remove -Variant $scenario.Variant)
      $null=Invoke-RidePlan $remove -WhatIf -Confirm:$false
      if(-not(Test-RideDesiredState $plan[0].Operation Present)){throw 'Portable removal preview changed presence.'}
      $removeRunId=Get-SavedRunId @(Invoke-RidePlan $remove -Confirm:$false)
      if(-not (Test-Path -LiteralPath $userFile)){throw 'Portable removal deleted user content.'}
      $repeatRemove=@(Invoke-RidePlan $remove -Confirm:$false)
      if('No changes were needed; no state record was created.' -notin $repeatRemove){throw 'Repeat portable removal was not idempotent.'}
      $null=Restore-RideRun -RunId $removeRunId -Confirm:$false
      if(-not (Test-RideDesiredState $plan[0].Operation Present)){throw 'Portable uninstall recovery failed.'}
    }
    if($profileFixture){
      $remove=@(Get-RideSingleOperationPlan -Id $scenario.Id -Action Remove -Variant $scenario.Variant)
      $null=Invoke-RidePlan $remove -WhatIf -Confirm:$false
      if(-not(Test-RideDesiredState $plan[0].Operation Present)){throw 'Removal preview changed presence.'}
      $removeRunId=Get-SavedRunId @(Invoke-RidePlan $remove -Confirm:$false)
      if((Get-RideCurrentState $plan[0].Operation).Present){throw 'Removal did not establish absence.'}
      if(-not(Test-Path -LiteralPath $profileFixture) -or [IO.File]::ReadAllText($profileFixture) -cne 'Keep existing profile data.'){throw 'Removal changed existing profile data.'}
      $repeatRemove=@(Invoke-RidePlan $remove -Confirm:$false)
      if('No changes were needed; no state record was created.' -notin $repeatRemove){throw 'Repeat removal was not idempotent.'}
      $null=Restore-RideRun -RunId $removeRunId -Confirm:$false
      if(-not(Test-RideDesiredState $plan[0].Operation Present)){throw 'Compensating removal recovery did not establish presence.'}
      $scenarioResult.RemovalRecoveryVersion=(Get-RideCurrentState $plan[0].Operation).DisplayVersion
    }
    $null=Restore-RideRun -RunId $runId -Confirm:$false
    if((Get-RideCurrentState $plan[0].Operation).Present){throw 'Restoration did not recover original absence.'}
    if($profileFixture){
      if(-not(Test-Path -LiteralPath $profileFixture) -or [IO.File]::ReadAllText($profileFixture) -cne 'Keep existing profile data.'){throw 'Recovery changed existing profile data.'}
      $scenarioResult.ProfilePreservation=$true
    }
    if($sessionFile){
      if(-not(Test-Path -LiteralPath $sessionFile) -or [IO.File]::ReadAllText($sessionFile) -cne "[Sessions\RIDEFixture]`r`nHostName=example.invalid`r`n" -or
        (Get-ItemProperty -LiteralPath $sessionFixture -Name HostName).HostName -cne 'example.invalid'){throw 'WinSCP removal/recovery changed session configuration.'}
      $scenarioResult.SessionPreservation=$true
    }
    $scenarioResult.Recovery=$true
    $null=Invoke-RidePlan @(Get-RideSingleOperationPlan -Id $scenario.Id -Action Remove -Variant $scenario.Variant) -Confirm:$false
    $scenarioResult.Status='Passed'
  }catch{
    $scenarioResult.Error=$_.Exception.Message
    if($scenario.Id -eq 'package.signal'){
      # Bounded product registration evidence; do not export unrelated registry data.
      $scenarioResult.FailureRegistration=@(Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object {$_.DisplayName -like 'Signal*'} | Select-Object -First 8 DisplayName,DisplayVersion,InstallLocation,UninstallString,QuietUninstallString)
    }
    Write-Warning "$($scenario.Id): $($scenarioResult.Error)"
  }
  $results.Add([pscustomobject]$scenarioResult)
  if($env:RIDE_TEST_EVIDENCE_PATH){$results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $env:RIDE_TEST_EVIDENCE_PATH $evidenceFile) -Encoding UTF8}
}
$results | Format-Table Id,Variant,Target,Status,Version -AutoSize
if($env:RIDE_TEST_EVIDENCE_PATH){$results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $env:RIDE_TEST_EVIDENCE_PATH $evidenceFile) -Encoding UTF8}
if(@($results | Where-Object { $_.Status -notin @('Passed','NotApplicable') }).Count){throw "Applications batch $Batch has failed scenarios; see application evidence."}
