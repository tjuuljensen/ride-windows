<#
.SYNOPSIS
  Validate one application migration batch in a disposable Windows guest.
.DESCRIPTION
  Exercises previews, install/repeat/remove and saved-run recovery. Selected
  application scenarios preserve user files and recover an explicit uninstall.
  With an evidence directory, appends closed-handle lifecycle progress records.
  Project Maker also retains its Inno Setup log for timeout diagnosis.
.PARAMETER Batch
  Installed applications (1), portable applications (2), Docker Desktop variants (3), Slack and Discord (4), Microsoft Visual C++ v14 (5), Artcraft machine-scope applications (6), ArtCraft Launcher (7), side-by-side Microsoft OpenJDK versions on Server 2025 (8), MiTeC InfoBar on Windows 11 (9), MiTeC Project Maker on Windows 11 (10), HashCheck on Windows 11 (11), or NTCore Explorer Suite on Windows 11 (12).
.PARAMETER PackageId
  For batch 12, the exact package ID package.ntcore-explorer-suite. No other package is accepted.
.PARAMETER Variant
  Limit batch 3 to one Docker Desktop variant. all-users runs only the elevated system-wide edition.
.PARAMETER PackageScope
  For ApplicationsBatch1, select all packages, packages that do not require an unelevated user, or packages that require an unelevated user.
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
.EXAMPLE
  .\Invoke-RideApplicationBatch.ps1 -Batch 3 -Variant all-users
  Exercise only Docker Desktop's elevated system-wide variant in the disposable guest.
.EXAMPLE
  .\Invoke-RideApplicationBatch.ps1 -Batch 8
  Exercise the four pinned Microsoft OpenJDK MSIs on Windows Server 2025.
.EXAMPLE
  .\Invoke-RideApplicationBatch.ps1 -Batch 9
  Exercise MiTeC InfoBar installation, removal, and saved-state recovery without launching it.
.EXAMPLE
  .\Invoke-RideApplicationBatch.ps1 -Batch 10
  Exercise MiTeC Project Maker installation, removal, and saved-state recovery without launching it.
.EXAMPLE
  .\Invoke-RideApplicationBatch.ps1 -Batch 12 -PackageId package.ntcore-explorer-suite
  Exercise only the pinned NTCore Explorer Suite installer lifecycle on Windows 11 without launching suite utilities.
.INPUTS
  None.
.OUTPUTS
  Scenario results; correlated evidence remains in the guest result directory.
.NOTES
  Compatibility: Windows PowerShell 5.1 on disposable Windows 11/Server 2025.
  Prerequisites: Elevated guest, RIDE_INTEGRATION_VM=1 and the VM test runner.
  Recovery: Saved-run restoration and host clean-checkpoint recovery.
  Owner: RIDE-Windows maintainers. Version: 0.19.4.
  Changelog: 0.19.4: Retain machine lifecycle stage progress and Project Maker installer diagnostics on timeout.
    0.19.3: Admit the exact Batch 12 candidate to the guest-only catalog and include its removal/recovery checks.
    0.19.2: Check HashCheck's observed four-part installed version without changing its release pin.
    0.19.1: Retain the HashCheck publisher installer log in collected guest evidence.
    0.19.0: Add exact-package Windows 11 acceptance selection for NTCore Explorer Suite.
    0.18.0: Add focused Windows 11 HashCheck ApplicationsBatch11 install/remove/recovery acceptance.
    0.16.0: Add Windows 11 MiTeC InfoBar ApplicationsBatch9 install/remove/recovery acceptance.
    0.15.3: Split ApplicationsBatch1 machine/user acceptance and retain user-worker phase diagnostics.
    0.15.2: Verify in-place uninstall preserves synthetic user data for every ApplicationsBatch1 vendor package.
    0.15.1: Exercise TMOG uninstall/recovery and preserve synthetic user data under LocalAppData.
    0.15.0: Exercise OpenJDK removal, repeat removal and removal recovery on Server 2025.
    0.14.9: Capture bounded failure stage and exception details for OpenJDK lifecycle diagnostics.
    0.14.8: Check exact OpenJDK package IDs; test launcher MSI registration without ARP entries.
    0.14.7: Capture bounded launcher registration and MSI event evidence when installation detection fails.
    0.14.6: Verify Artcraft MSI uninstallation preserves user profile data.
    0.14.5: Verify pinned Artcraft versions and full install/uninstall recovery in ApplicationsBatch6 and ApplicationsBatch7.
    0.14.3: Use the exported engine state reader when checking whether prerequisite-dependent packages are installed.
    0.14.2: Normalize MSI diagnostic rows and capture one JSON string before incremental evidence writes.
    0.14.1: Preserve the coordinator evidence-file path while building the limited-worker command.
    0.14.0: Keep limited-worker paths separate from the coordinator evidence destination.
    0.13.0: Checkpoint each scenario result as a compact JSON record without reserializing prior rows.
    0.12.0: Add Server 2025 lifecycle, runtime and shared-Java-default preservation checks for the four side-by-side Microsoft OpenJDK packages.
    0.11.0: Allow 45 minutes for ApplicationsBatch1's limited-user lifecycle and retain diagnostic MSI output for Phoenix Protector.
    0.10.0: Continue machine-scope scenarios after a limited-user worker reports partial failure; retain missing user results explicitly.
    0.9.0: Add Windows 11 current-user ArtCraft Launcher lifecycle batch without launching it.
    0.8.0: Add a dedicated Windows 11 lifecycle batch for the twelve Artcraft machine-scope apps; license-review markers do not gate technical selection.
    0.7.0: Route application scenarios by declared supported/candidate targets.
    0.6.0: Add focused Microsoft Visual C++ v14 lifecycle and recovery acceptance.
    0.5.0: Add focused current-user Slack and Discord lifecycle acceptance.
    0.4.7: Avoid variant parameter shadowing in package-selection loops.
    0.4.6: Support focused Docker Desktop variant acceptance.
    0.4.5: Allow 60 minutes for Docker Desktop's limited-user lifecycle.
    0.4.4: Grant and remove batch-logon rights for the temporary guest account only.
    0.4.3: Start the registered task object and collect focused guest event history.
    0.4.2: Retain limited-worker task startup diagnostics before cleanup.
    0.4.1: Use a temporary standard account and fail promptly on worker startup.
    0.4.0: Validate Thunderbird in a limited guest context.
    0.3.0: Check WinSCP portable signatures and session preservation.
    0.2.0: Check Chrome/Signal profile preservation and removal recovery.
    0.1.0: Add two package-only migration suites.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([ValidateSet(1,2,3,4,5,6,7,8,9,10,11,12)][int] $Batch=1,[ValidateSet('all-users')][string] $Variant,[ValidateSet('All','Machine','User')][string] $PackageScope='All',[ValidateSet('package.ntcore-explorer-suite')][string] $PackageId,[switch] $Version,[switch] $UnelevatedChild,[string] $ExpectedUserSid,[string] $ExpectedLocalAppData)
$script:ScriptVersion='0.19.4'
if($Version){$script:ScriptVersion;return}
$ErrorActionPreference='Stop'
if($env:RIDE_INTEGRATION_VM -ne '1'){throw 'Run application scenarios only through the disposable-VM runner.'}
if($Variant -and $Batch -ne 3){throw 'Variant selection is supported only by application batch 3.'}
if($Batch -eq 12 -and $PackageId -cne 'package.ntcore-explorer-suite'){throw 'ApplicationsBatch12 requires exactly -PackageId package.ntcore-explorer-suite.'}
if($Batch -ne 12 -and $PackageId){throw '-PackageId is supported only by ApplicationsBatch12.'}
$workerIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
$workerElevated=([Security.Principal.WindowsPrincipal]::new($workerIdentity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($UnelevatedChild -and ($workerElevated -or $workerIdentity.User.Value -cne $ExpectedUserSid)){throw 'Limited worker identity or elevation does not match the authorized guest context.'}
if($UnelevatedChild -and ([Environment]::GetFolderPath('LocalApplicationData') -ine $ExpectedLocalAppData)){throw 'Limited worker profile does not match the authorized guest user.'}
if(-not $UnelevatedChild -and ($ExpectedUserSid -or $ExpectedLocalAppData)){throw 'Identity correlation requires the internal limited worker.'}
if(-not $PSCmdlet.ShouldProcess('Disposable guest',"Run applications batch $Batch")){return}

function Get-RideOpenJdkPreservationSnapshot {
  $state=[ordered]@{
    MachineJavaHome=[Environment]::GetEnvironmentVariable('JAVA_HOME','Machine')
    MachinePath=[Environment]::GetEnvironmentVariable('Path','Machine')
    UserJavaHome=[Environment]::GetEnvironmentVariable('JAVA_HOME','User')
    UserPath=[Environment]::GetEnvironmentVariable('Path','User')
    JarAssociationTrees=@()
  }
  foreach($root in @(
    'Registry::HKEY_LOCAL_MACHINE\Software\Classes\.jar',
    'Registry::HKEY_CURRENT_USER\Software\Classes\.jar',
    'Registry::HKEY_CLASSES_ROOT\.jar',
    'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jar'
  )){
    $rootEntry=[ordered]@{Path=$root;Exists=$false;Keys=@()}
    if(Test-Path -LiteralPath $root){
      $rootEntry.Exists=$true
      $keyPaths=@($root)+@(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction Stop | Sort-Object PSPath | ForEach-Object PSPath)
      foreach($keyPath in $keyPaths){
        $key=Get-Item -LiteralPath $keyPath -ErrorAction Stop
        $values=[ordered]@{}
        foreach($valueName in @($key.GetValueNames() | Sort-Object)){
          $value=$key.GetValue($valueName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
          if($value -is [byte[]]){$value=[Convert]::ToBase64String($value)}
          $values[$valueName]=$value
        }
        $rootEntry['Keys']+=@([pscustomobject]@{Path=$key.Name;Values=$values})
      }
    }
    $state.JarAssociationTrees+=@([pscustomobject]$rootEntry)
  }
  ConvertTo-Json -InputObject ([pscustomobject]$state) -Depth 10 -Compress
}

function Assert-RideOpenJdkPreservation {
  param([Parameter(Mandatory)][string]$Expected,[Parameter(Mandatory)][string]$Stage)
  $actual=Get-RideOpenJdkPreservationSnapshot
  if($actual -cne $Expected){throw "OpenJDK $Stage changed JAVA_HOME, PATH or .jar association state."}
}

function Invoke-RideOpenJdkVersionCommand {
  param([Parameter(Mandatory)][string]$Path)
  $startInfo=New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName=$Path
  $startInfo.Arguments='-version'
  $startInfo.UseShellExecute=$false
  $startInfo.CreateNoWindow=$true
  $startInfo.RedirectStandardOutput=$true
  $startInfo.RedirectStandardError=$true
  $process=New-Object System.Diagnostics.Process
  $process.StartInfo=$startInfo
  try {
    if(-not $process.Start()){throw "Could not start '$Path'."}
    $standardOutput=$process.StandardOutput.ReadToEnd()
    $standardError=$process.StandardError.ReadToEnd()
    $process.WaitForExit()
    [pscustomobject]@{ExitCode=$process.ExitCode;StandardOutput=$standardOutput;StandardError=$standardError}
  } finally { $process.Dispose() }
}

function Add-RideApplicationBatchResult {
  param(
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$JsonRecords,
    [Parameter(Mandatory)][object]$Result,
    [string]$EvidencePath
  )
  $null=$Results.Add($Result)
  if($EvidencePath){
    $serializedResult=ConvertTo-Json -InputObject $Result -Depth 8 -Compress
    if($serializedResult -isnot [string]){throw 'Application scenario serialization did not return one JSON string.'}
    $null=$JsonRecords.Add($serializedResult)
    $json='['+($JsonRecords -join ',')+']'
    Set-Content -LiteralPath $EvidencePath -Value $json -Encoding UTF8
  }
}

function New-RideApplicationUserDataFixtures {
  param(
    [Parameter(Mandatory)][string]$PackageId,
    [Parameter(Mandatory)][hashtable]$Roots
  )
  $token = [guid]::NewGuid().ToString('N')
  $definitions = switch ($PackageId) {
    'package.vscode' { @(@{ Name='VS Code user settings'; Root='Roaming'; RelativePath="Code\User\RIDE-Acceptance-{token}\settings.json"; Content='{"rideAcceptance":"preserve"}' }, @{ Name='VS Code user extensions'; Root='Profile'; RelativePath=".vscode\extensions\ride.acceptance-{token}\package.json"; Content='{"name":"ride-acceptance","version":"1.0.0"}' }) }
    'package.firefox' { @(@{ Name='Firefox profile preferences'; Root='Roaming'; RelativePath="Mozilla\Firefox\Profiles\ride-acceptance-{token}.default-release\prefs.js"; Content='user_pref("ride.acceptance.preserve", true);' }) }
    'package.sqlitebrowser' { @(@{ Name='User-selected SQLite Browser data'; Root='Documents'; RelativePath="RIDE Acceptance Data\DB Browser\{token}\user-data.txt"; Content='Synthetic user-selected database data; do not delete.' }) }
    'package.autopsy' { @(@{ Name='Autopsy user settings'; Root='Roaming'; RelativePath="autopsy\config\ride-acceptance-{token}.properties"; Content='ride.acceptance.preserve=true' }, @{ Name='Autopsy case data'; Root='Documents'; RelativePath="RIDE Acceptance Data\Autopsy\case-{token}\case.aut"; Content='Synthetic case data; do not delete.' }) }
    'package.chrome' { @(@{ Name='Chrome user profile'; Root='Local'; RelativePath="Google\Chrome\User Data\RIDE-Acceptance-{token}\Preferences"; Content='{"rideAcceptance":"preserve"}' }) }
    'package.wireshark' { @(@{ Name='Wireshark personal configuration'; Root='Roaming'; RelativePath="Wireshark\profiles\RIDE Acceptance {token}\preferences"; Content='gui.toolbar_main_show: TRUE' }) }
    'package.signal' { @(@{ Name='Signal user profile'; Root='Roaming'; RelativePath="Signal\ride-preservation-{token}.txt"; Content='Keep existing profile data.' }) }
    'package.thunderbird' { @(@{ Name='Thunderbird user profile'; Root='Roaming'; RelativePath="Thunderbird\Profiles\ride-acceptance-{token}.default\prefs.js"; Content='user_pref("ride.acceptance.preserve", true);' }) }
    'package.tmog' { @(@{ Name='TMOG user data'; Root='Local'; RelativePath="TMOG\ride-preservation-{token}.txt"; Content='Keep existing profile data.' }) }
    'package.phoenix-protector' { @(@{ Name='Phoenix Protector user project data'; Root='Documents'; RelativePath="RIDE Acceptance Data\Phoenix Protector\sample-project-{token}.txt"; Content='Synthetic user project data; do not delete.' }) }
    'package.gpg4win' { @(@{ Name='GnuPG user configuration'; Root='Roaming'; RelativePath="gnupg\ride-acceptance-{token}.conf"; Content='# RIDE synthetic user configuration; no keys or certificates.' }) }
    default { @() }
  }
  $fixtures = [System.Collections.Generic.List[object]]::new()
  foreach ($definition in $definitions) {
    if (-not $Roots.ContainsKey($definition.Root)) { throw "Missing user-data root '$($definition.Root)' for $PackageId." }
    $root = [IO.Path]::GetFullPath([string]$Roots[$definition.Root])
    $relativePath = ([string]$definition.RelativePath).Replace('{token}', $token)
    $path = [IO.Path]::GetFullPath((Join-Path $root $relativePath))
    $prefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "User-data fixture escaped its declared root for $PackageId." }
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    [IO.File]::WriteAllText($path, [string]$definition.Content, [Text.UTF8Encoding]::new($false))
    $fixtures.Add([pscustomobject]@{
      Name = [string]$definition.Name
      Path = $path
      RelativePath = $relativePath
      Root = [string]$definition.Root
      Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    })
  }
  return $fixtures.ToArray()
}

function Assert-RideApplicationUserDataPreserved {
  param(
    [Parameter(Mandatory)][object[]]$Fixtures,
    [Parameter(Mandatory)][string]$Stage
  )
  foreach ($fixture in $Fixtures) {
    if (-not (Test-Path -LiteralPath $fixture.Path -PathType Leaf)) { throw "$Stage removed user data fixture '$($fixture.Name)'." }
    $actualHash = (Get-FileHash -LiteralPath $fixture.Path -Algorithm SHA256).Hash
    if ($actualHash -cne $fixture.Sha256) { throw "$Stage modified user data fixture '$($fixture.Name)'." }
  }
}

Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PackageSelection.psm1') -Force
$target=Get-RidePlatform
if($target -notin @('Windows 11','Windows Server 2025')){throw "Application acceptance requires the declared Windows 11/Server 2025 guests; found $target."}
if($Batch -in @(5,6,7) -and $target -ne 'Windows 11'){throw "Application candidate batch $Batch is limited to Windows 11; Server support has not been selected."}
if($Batch -eq 8 -and $target -ne 'Windows Server 2025'){throw 'ApplicationsBatch8 is limited to Windows Server 2025.'}
if($Batch -eq 9 -and $target -ne 'Windows 11'){throw 'ApplicationsBatch9 is limited to Windows 11.'}
if($Batch -eq 10 -and $target -ne 'Windows 11'){throw 'ApplicationsBatch10 is limited to Windows 11.'}
if($Batch -eq 11 -and $target -ne 'Windows 11'){throw 'ApplicationsBatch11 is limited to Windows 11.'}
if($Batch -eq 12 -and $target -ne 'Windows 11'){throw 'ApplicationsBatch12 is limited to Windows 11.'}
if($PackageScope -ne 'All' -and $Batch -ne 1){throw 'PackageScope is supported only for ApplicationsBatch1.'}
$guestOs=Get-CimInstance Win32_OperatingSystem
$installationType=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType -ErrorAction Stop).InstallationType
$catalog=Get-RideCatalog
$scenarios=@()
$targetExcluded=@()
foreach($package in $catalog.Operations | Where-Object Kind -eq 'Package'){
  $names=if($package.Variants){@($package.Variants.Keys)}else{@('installed')}
  foreach($packageVariant in $names){
    $selected=Resolve-RidePackageSelection -Operation $package -Variant $packageVariant
    $batchMatch=if($Batch -eq 8){$selected.MigrationBatch -eq 'OpenJDKCompatibility'}elseif($Batch -eq 12){$package.Id -ceq $PackageId}else{$selected.MigrationBatch -eq "ApplicationsBatch$Batch"}
    if($batchMatch -and (-not $Variant -or $packageVariant -eq $Variant)){
      if(Test-RidePackageTargetEligibility -Operation $selected -Target $target){$scenarios+=@{Id=$package.Id;Variant=$packageVariant;Selected=$selected}}
      else{$targetExcluded+=@{Id=$package.Id;Variant=$packageVariant;Selected=$selected}}
    }
  }
}
if(-not $scenarios.Count){throw 'No application scenarios were selected.'}
if($PackageScope -eq 'Machine'){$scenarios=@($scenarios|Where-Object {-not $_.Selected.RequiresUnelevatedUser})}
elseif($PackageScope -eq 'User'){$scenarios=@($scenarios|Where-Object {$_.Selected.RequiresUnelevatedUser})}
if(-not $scenarios.Count){throw "ApplicationsBatch$Batch has no packages in the selected '$PackageScope' scope."}
if($Batch -eq 5 -and ($scenarios.Count -ne 1 -or $scenarios[0].Id -cne 'package.vcredist-v14-x64')){throw 'ApplicationsBatch5 must select exactly the Microsoft Visual C++ v14 x64 package.'}
if($Batch -eq 6){
  $expectedIds=@('package.photocraft','package.vectorcraft','package.filmcraft','package.lightcraft','package.pdfcraft','package.effectcraft','package.designcraft','package.wordcraft','package.soundcraft','package.deckcraft','package.cadcraft','package.gridcraft')
  $actualIds=@($scenarios | ForEach-Object Id | Sort-Object)
  if($actualIds.Count -ne $expectedIds.Count -or (@($actualIds) -join '|') -cne (@($expectedIds | Sort-Object) -join '|')){throw 'ApplicationsBatch6 must select exactly the twelve declared Artcraft machine-scope apps; the separate launcher is excluded.'}
}
if($Batch -eq 7 -and ($scenarios.Count -ne 1 -or $scenarios[0].Id -cne 'package.artcraft-launcher')){throw 'ApplicationsBatch7 must select exactly the current-user ArtCraft Launcher package.'}
if($Batch -eq 8){
  $expectedIds=@('microsoft-openjdk-25','microsoft-openjdk-21','microsoft-openjdk-17','microsoft-openjdk-11')
  $actualIds=@($scenarios | ForEach-Object {$_.Selected.PackageId} | Sort-Object)
  if($actualIds.Count -ne $expectedIds.Count -or (@($actualIds) -join '|') -cne (@($expectedIds | Sort-Object) -join '|')){throw 'ApplicationsBatch8 must select exactly the four pinned Microsoft OpenJDK compatibility packages.'}
}
if($Batch -eq 9 -and ($scenarios.Count -ne 1 -or $scenarios[0].Id -cne 'package.mitec-infobar')){throw 'ApplicationsBatch9 must select exactly MiTeC InfoBar 4.6.2.'}
if($Batch -eq 10 -and ($scenarios.Count -ne 1 -or $scenarios[0].Id -cne 'package.mitec-project-maker')){throw 'ApplicationsBatch10 must select exactly MiTeC Project Maker 1.9.0.'}
if($Batch -eq 11 -and ($scenarios.Count -ne 1 -or $scenarios[0].Id -cne 'package.hashcheck-shell-extension')){throw 'ApplicationsBatch11 must select exactly HashCheck Shell Extension 2.6.3.'}
if($Batch -eq 12 -and ($scenarios.Count -ne 1 -or $scenarios[0].Id -cne 'package.ntcore-explorer-suite')){throw 'ApplicationsBatch12 must select exactly the pinned NTCore Explorer Suite candidate.'}
$results=New-Object System.Collections.Generic.List[object]
$jsonResults=New-Object System.Collections.Generic.List[string]
$evidenceFile=if($UnelevatedChild){"applications-batch$Batch-user.json"}else{"applications-batch$Batch.json"}
$evidencePath=if($env:RIDE_TEST_EVIDENCE_PATH){Join-Path $env:RIDE_TEST_EVIDENCE_PATH $evidenceFile}else{$null}
if(-not $UnelevatedChild){
  $targetExcluded | ForEach-Object {
    $eligibleTargets=@($_.Selected.SupportedTargets)+@($_.Selected.CandidateTargets)
    Add-RideApplicationBatchResult -Results $results -JsonRecords $jsonResults -Result ([pscustomobject][ordered]@{Id=$_.Id;Variant=$_.Variant;Target=$target;OS=$guestOs.Caption;Build=$guestOs.BuildNumber;InstallationType=$installationType;Applicability="Not selected: catalog supports or candidates this package only for $($eligibleTargets -join ', ').";Status='NotApplicable';Version=$null;Error=$null;Recovery=$true;ProfilePreservation=$null;UserDataPreservation=$null;UserDataFixtures=@();RemovalRecoveryVersion=$null;RecoveryMode='No lifecycle actions performed for an ineligible target'}) -EvidencePath $evidencePath
  }
}
if($UnelevatedChild){
  # The limited user writes acquisition evidence in its own output directory.
  # The elevated coordinator merges it after the worker has stopped.
  & (Get-Module -All RIDE-Packages | Select-Object -First 1) {param($path) $script:PSDefaultParameterValues=@{'Save-RidePackageArtifact:ObservationPath'=$path}} (Join-Path $env:RIDE_TEST_EVIDENCE_PATH 'application-user-observations.json')
}
if(-not $UnelevatedChild -and @($scenarios | Where-Object {$_.Selected.RequiresUnelevatedUser}).Count){
  if(-not $workerElevated -or -not $env:RIDE_TEST_EVIDENCE_PATH){throw 'The limited-worker coordinator requires the elevated disposable guest and an evidence directory.'}
  $limitedScenarioIds=@($scenarios | Where-Object {$_.Selected.RequiresUnelevatedUser} | ForEach-Object { "$($_.Id)|$($_.Variant)" })
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
    $workerEvidencePath=$workerRoot.Replace("'","''")
    $localAppData=$localAppDataPath.Replace("'","''")
    $command="try{[IO.File]::WriteAllText('$workerEvidencePath/application-user-bootstrap.log', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value);`$env:RIDE_INTEGRATION_VM='1';`$env:RIDE_TEST_EVIDENCE_PATH='$workerEvidencePath';`$env:RIDE_TEST_RUN_ID='$($env:RIDE_TEST_RUN_ID)'; & '$scriptPath' -Batch $Batch -UnelevatedChild -ExpectedUserSid '$($testUser.SID.Value)' -ExpectedLocalAppData '$localAppData' *> '$workerEvidencePath/application-user-worker.log';exit 0}catch{[IO.File]::AppendAllText('$workerEvidencePath/application-user-worker.log',(`$_ | Out-String));exit 1}"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action=New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded" -WorkingDirectory (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $workerTimeoutMinutes=if($Batch -eq 1){60}elseif($Batch -eq 3){45}else{20}
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $workerTimeoutMinutes) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
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
    $deadline=[datetime]::UtcNow.AddMinutes($workerTimeoutMinutes+1)
    do{
      Start-Sleep -Seconds 2
      $info=Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\RIDE\'
      $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\'
      if($info.LastTaskResult -eq 267014){throw "Limited worker exceeded its $workerTimeoutMinutes-minute execution limit (267014)."}
      if($info.LastTaskResult -gt 65535 -and $info.LastTaskResult -notin @(267009,267011)){throw "Limited worker could not start: $($info.LastTaskResult)."}
      if($info.LastRunTime.Year -le 2000 -and [datetime]::UtcNow -gt $startupDeadline){throw 'Limited worker did not start within 60 seconds; inspect task logon rights and run conditions.'}
      # The task state and last-result updates are not atomic.
      if($info.LastRunTime.Year -gt 2000 -and $task.State -notin @('Running','Queued') -and $info.LastTaskResult -ne 267009){break}
    }while([datetime]::UtcNow -lt $deadline)
    if($task.State -eq 'Running' -or $info.LastTaskResult -eq 267009){Stop-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\';throw "Limited application worker exceeded its $workerTimeoutMinutes-minute execution limit."}
    if(-not(Test-Path -LiteralPath $childPath)){throw "Limited application worker failed: $($info.LastTaskResult); no partial scenario evidence was produced. See application-user-worker.log."}
    if($info.LastTaskResult -ne 0){Write-Warning "Limited application worker exited with $($info.LastTaskResult); retaining its partial scenario results and continuing machine-scope scenarios."}
    $limitedRows=Get-Content -LiteralPath $childPath -Raw | ConvertFrom-Json
    if($null -eq $limitedRows){$limitedRows=@()}
    elseif($limitedRows -isnot [array]){$limitedRows=@($limitedRows)}
    while($limitedRows.Count -eq 1 -and $limitedRows[0] -is [array]){$limitedRows=@($limitedRows[0])}
    foreach($row in $limitedRows){
      if($row.ExecutionSid -cne $testUser.SID.Value -or $row.Elevated -ne $false -or $row.LocalAppData -ine $localAppDataPath){throw 'Limited application evidence identity mismatch.'}
      $row | Add-Member -NotePropertyName TestUserSid -NotePropertyValue $testUser.SID.Value
      Add-RideApplicationBatchResult -Results $results -JsonRecords $jsonResults -Result $row -EvidencePath $evidencePath
    }
    $completedLimitedIds=@($limitedRows | ForEach-Object { "$($_.Id)|$($_.Variant)" })
    foreach($missing in @($limitedScenarioIds | Where-Object {$_ -notin $completedLimitedIds})){
      $parts=$missing.Split('|',2)
      Add-RideApplicationBatchResult -Results $results -JsonRecords $jsonResults -Result ([pscustomobject]@{Id=$parts[0];Variant=$parts[1];Target=$target;Scope='User';Applicability='Applicable to deployment lifecycle';Status='Failed';Error="Limited application worker exited with $($info.LastTaskResult) before producing a scenario result.";Recovery=$false;ExecutionSid=$testUser.SID.Value;Elevated=$false;LocalAppData=$localAppDataPath;TestUserSid=$testUser.SID.Value}) -EvidencePath $evidencePath
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
        foreach($name in @('application-user-bootstrap.log','application-user-worker.log','application-user-progress.jsonl','application-user-observations.json',"applications-batch$Batch-user.json")){
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

function Write-RideApplicationProgress {
  param([Parameter(Mandatory)][string]$PackageId,[Parameter(Mandatory)][string]$Stage)
  if(-not $env:RIDE_TEST_EVIDENCE_PATH){return}
  $fileName=if($UnelevatedChild){'application-user-progress.jsonl'}else{'application-progress.jsonl'}
  $path=Join-Path $env:RIDE_TEST_EVIDENCE_PATH $fileName
  $entry=[ordered]@{AtUtc=[datetime]::UtcNow.ToString('o');PackageId=$PackageId;Stage=$Stage}
  [IO.File]::AppendAllText($path,($entry|ConvertTo-Json -Compress)+[Environment]::NewLine)
}
# Test-only support metadata lives in memory inside this guarded guest. It is
# never written back to the production catalog or used as acceptance evidence.
$testCatalog=Get-RideCatalog
foreach($package in $testCatalog.Operations | Where-Object Kind -eq 'Package'){
  if(($package.MigrationBatch -like 'ApplicationsBatch*' -or $package.MigrationBatch -eq 'OpenJDKCompatibility' -or ($Batch -eq 12 -and $package.Id -ceq 'package.ntcore-explorer-suite')) -and (Test-RidePackageTargetEligibility -Operation $package -Target $target)){
    $package.SupportedTargets=@($package.SupportedTargets)+@($target) | Select-Object -Unique
    $package.PendingAcceptance=$false
  }
  foreach($catalogVariant in $package.Variants.Values){
    if(($catalogVariant.MigrationBatch -like 'ApplicationsBatch*' -or $catalogVariant.MigrationBatch -eq 'OpenJDKCompatibility') -and (Test-RidePackageTargetEligibility -Operation $catalogVariant -Target $target)){
      $catalogVariant.SupportedTargets=@($catalogVariant.SupportedTargets)+@($target) | Select-Object -Unique
      $catalogVariant.PendingAcceptance=$false
    }
  }
}
& (Get-Module RIDE.Engine) {param($candidateCatalog) $script:RideLibraryContext=@{Catalog=$candidateCatalog}} $testCatalog
foreach($scenario in $scenarios){
  $operation=Get-RideOperation $scenario.Id
  $scenarioStage='Build installation plan'
  Write-RideApplicationProgress -PackageId $scenario.Id -Stage $scenarioStage
  $phoenixMsiLog=$null
  if($scenario.Id -eq 'package.mitec-project-maker' -and $env:RIDE_TEST_EVIDENCE_PATH){
    # Inno Setup's documented LOG switch changes diagnostics only. Keep the
    # log outside TEMP so partial collection can retain it after a timeout.
    $projectMakerLog=Join-Path $env:RIDE_TEST_EVIDENCE_PATH 'project-maker-install.log'
    $operation.InstallerArguments=[string]$operation.InstallerArguments+' /LOG="'+$projectMakerLog+'"'
  }
  if($scenario.Id -eq 'package.hashcheck-shell-extension' -and $env:RIDE_TEST_EVIDENCE_PATH){
    # The publisher supports /LOG=; keep its diagnostic outside guest TEMP so
    # controller collection retains the failed step before checkpoint recovery.
    $hashCheckLog=Join-Path $env:RIDE_TEST_EVIDENCE_PATH 'hashcheck-install.log'
    $operation.InstallerArguments=[string]$operation.InstallerArguments+' /LOG="'+$hashCheckLog+'"'
  }
  if($scenario.Id -eq 'package.phoenix-protector' -and $env:RIDE_TEST_EVIDENCE_PATH){
    $phoenixMsiLog=Join-Path $env:RIDE_TEST_EVIDENCE_PATH 'phoenix-protector-install.msi.log'
    $operation.InstallerArguments=[string]$operation.InstallerArguments+' /L*v "'+$phoenixMsiLog+'"'
  }
  $package=Resolve-RidePackageSelection $operation -Variant $scenario.Variant
  $scenarioResult=[ordered]@{Id=$scenario.Id;Variant=$scenario.Variant;Target=$target;OS=$guestOs.Caption;Build=$guestOs.BuildNumber;InstallationType=$installationType;Scope=$package.Scope;Provider=$package.DownloadProvider;Applicability='Applicable to deployment lifecycle';Status='Failed';Version=$null;Error=$null;Recovery=$false;ProfilePreservation=$null;UserDataPreservation=$null;UserDataFixtures=@();RemovalRecoveryVersion=$null;Checks=@();RecoveryMode=if($package.InstallerType -eq 'Portable'){'Exact owned-file recovery'}else{'Compensating presence recovery; previous-version recovery unavailable'}}
  $scenarioResult.ExecutionSid=$workerIdentity.User.Value
  $scenarioResult.Elevated=$workerElevated
  $scenarioResult.LocalAppData=[Environment]::GetFolderPath('LocalApplicationData')
  if($package.RequiresDesktopExperience -and $target -like 'Windows Server*' -and $installationType -ne 'Server'){
    $scenarioResult.Applicability='Unavailable: requires Desktop Experience';$scenarioResult.Status='NotApplicable';$scenarioResult.Recovery=$true
    Add-RideApplicationBatchResult -Results $results -JsonRecords $jsonResults -Result ([pscustomobject]$scenarioResult) -EvidencePath $evidencePath;continue
  }
  try{
    $scenarioStage='Read pre-install state'
    Write-RideApplicationProgress -PackageId $scenario.Id -Stage $scenarioStage
    $openJdkBaseline=if($Batch -eq 8){Get-RideOpenJdkPreservationSnapshot}else{$null}
    $plan=@(Get-RideSingleOperationPlan -Id $scenario.Id -Action Install -Variant $scenario.Variant)
    $before=Get-RideCurrentState $plan[0].Operation
    if($before.Present -and $scenario.Id -eq 'package.vcredist-v14-x64'){
      $scenarioResult.Applicability='Not run: an adequate shared v14 runtime is already installed; preserving the checkpoint baseline.'
      $scenarioResult.Version=$before.DisplayVersion
      $scenarioResult.Recovery=$true
      $scenarioResult.Status='NotApplicable'
      Add-RideApplicationBatchResult -Results $results -JsonRecords $jsonResults -Result ([pscustomobject]$scenarioResult) -EvidencePath $evidencePath
      continue
    }
    if($scenario.Id -eq 'package.vcredist-v14-x64'){
      $dependentOperations=@((Get-RideCatalog).Operations|Where-Object PrerequisitePackageId -eq $scenario.Id)
      $installedDependents=@($dependentOperations|Where-Object { (Get-RideCurrentState $_).Present })
      if($installedDependents.Count){
        $scenarioResult.Applicability='Not run: catalog-dependent package(s) are already installed; preserving the checkpoint baseline.'
        $scenarioResult.Dependents=@($installedDependents.Id)
        $scenarioResult.Recovery=$true
        $scenarioResult.Status='NotApplicable'
        Add-RideApplicationBatchResult -Results $results -JsonRecords $jsonResults -Result ([pscustomobject]$scenarioResult) -EvidencePath $evidencePath
        continue
      }
    }
    if($before.Present){throw 'Clean application test guest unexpectedly contains this edition.'}
    if($scenario.Id -eq 'package.vcredist-v14-x64'){$scenarioResult.OriginalVersion=$before.DisplayVersion}
    $profileFixture=$null
    $userDataFixtures=@()
    $sessionFixture=$null
    $sessionFile=$null
    if($Batch -eq 1){
      $dataRoots=@{
        Roaming=[Environment]::GetFolderPath('ApplicationData')
        Local=[Environment]::GetFolderPath('LocalApplicationData')
        Profile=[Environment]::GetFolderPath('UserProfile')
        Documents=[Environment]::GetFolderPath('MyDocuments')
      }
      $userDataFixtures=@(New-RideApplicationUserDataFixtures -PackageId $scenario.Id -Roots $dataRoots)
      if(-not $userDataFixtures.Count){throw "ApplicationsBatch1 package '$($scenario.Id)' has no user-data preservation fixture."}
      $profileFixture=$userDataFixtures[0].Path
      $scenarioResult.UserDataFixtures=@($userDataFixtures | ForEach-Object { [pscustomobject]@{Name=$_.Name;Root=$_.Root;RelativePath=$_.RelativePath;Sha256=$_.Sha256} })
    }elseif($scenario.Id -in @('package.chrome','package.signal','package.thunderbird','package.slack','package.discord')){
      $profileRoot=if($scenario.Id -eq 'package.chrome'){Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Google/Chrome/User Data'}elseif($scenario.Id -eq 'package.thunderbird'){Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Thunderbird'}elseif($scenario.Id -eq 'package.slack'){Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Slack'}elseif($scenario.Id -eq 'package.discord'){Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'discord'}else{Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Signal'}
      New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
      $profileFixture=Join-Path $profileRoot ('ride-preservation-'+[guid]::NewGuid().ToString('N')+'.txt')
      [IO.File]::WriteAllText($profileFixture,'Keep existing profile data.')
    }elseif($scenario.Id -eq 'package.tmog'){
      $profileRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'TMOG'
      New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
      $profileFixture=Join-Path $profileRoot ('ride-preservation-'+[guid]::NewGuid().ToString('N')+'.txt')
      [IO.File]::WriteAllText($profileFixture,'Keep existing profile data.')
    }elseif($Batch -eq 6){
      $profileDirectory=[string]$package.Name
      if($scenario.Id -eq 'package.pdfcraft'){$profileDirectory=Join-Path $profileDirectory 'data'}
      $profileRoot=Join-Path ([Environment]::GetFolderPath('ApplicationData')) $profileDirectory
      New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
      $profileFixture=Join-Path $profileRoot ('ride-preservation-'+[guid]::NewGuid().ToString('N')+'.txt')
      [IO.File]::WriteAllText($profileFixture,'Keep existing profile data.')
    }elseif($Batch -eq 7){
      $profileRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ArtCraft Launcher'
      New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
      $profileFixture=Join-Path $profileRoot ('ride-preservation-'+[guid]::NewGuid().ToString('N')+'.txt')
      [IO.File]::WriteAllText($profileFixture,'Keep existing profile data.')
    }
    if($profileFixture -and $Batch -ne 1){$scenarioResult.ProfilePreservationPath=$profileRoot}
    $scenarioStage='Preview installation'
    Write-RideApplicationProgress -PackageId $scenario.Id -Stage $scenarioStage
    $null=Invoke-RidePlan $plan -WhatIf -Confirm:$false
    if((Get-RideCurrentState $plan[0].Operation).Present){throw 'Install preview changed package state.'}
    $scenarioStage='Install package'
    Write-RideApplicationProgress -PackageId $scenario.Id -Stage $scenarioStage
    $runId=Get-SavedRunId @(Invoke-RidePlan $plan -Confirm:$false)
    $scenarioStage='Verify installed package state'
    Write-RideApplicationProgress -PackageId $scenario.Id -Stage $scenarioStage
    $installed=Get-RideCurrentState $plan[0].Operation
    if(-not (Test-RideDesiredState $plan[0].Operation Present)){throw 'Installation did not establish the desired state.'}
    if($userDataFixtures.Count){Assert-RideApplicationUserDataPreserved -Fixtures $userDataFixtures -Stage 'Package installation'}elseif($profileFixture -and (-not(Test-Path -LiteralPath $profileFixture) -or [IO.File]::ReadAllText($profileFixture) -cne 'Keep existing profile data.')){throw 'Installation changed existing profile data.'}
    $scenarioResult.Version=$installed.DisplayVersion
    if($Batch -in @(6,7,9,10,11)){
      # HashCheck release 2.6.3 registers DisplayVersion 2.6.3.0; retain an
      # exact assertion rather than loosening version checks for other packages.
      $expectedInstalledVersion=if($Batch -eq 11){'2.6.3.0'}else{[string]$package.PackageVersion}
      if([string]$installed.DisplayVersion -cne $expectedInstalledVersion){throw "Installed package version '$($installed.DisplayVersion)' does not match expected installed version '$expectedInstalledVersion' for release '$($package.PackageVersion)'."}
      $scenarioResult.Checks+=@('RIDEManagedInstall','PinnedPackageVersion')
    }
    if($Batch -eq 8){
      $scenarioStage='Verify OpenJDK install directory and executables'
      $installedDirectory=([IO.Path]::GetFullPath([string]$installed.InstallLocation)).TrimEnd('\')
      $expectedDirectory=([IO.Path]::GetFullPath([string]$package.InstallDirectory)).TrimEnd('\')
      if($installedDirectory -ine $expectedDirectory){throw "OpenJDK installed outside its dedicated directory: $($installed.InstallLocation)"}
      $javaBin=Join-Path $package.InstallDirectory 'bin'
      $javaPath=Join-Path $javaBin 'java.exe'
      $javacPath=Join-Path $javaBin 'javac.exe'
      if(-not(Test-Path -LiteralPath $javaPath -PathType Leaf) -or -not(Test-Path -LiteralPath $javacPath -PathType Leaf)){throw 'OpenJDK runtime and compiler executables were not both installed in the dedicated directory.'}
      $scenarioStage='Run java.exe -version'
      $javaResult=Invoke-RideOpenJdkVersionCommand -Path $javaPath
      $scenarioStage='Run javac.exe -version'
      $javacResult=Invoke-RideOpenJdkVersionCommand -Path $javacPath
      $javaOutput=@(($javaResult.StandardOutput+$javaResult.StandardError) -split '\r?\n' | Where-Object {$_})
      $javacOutput=@(($javacResult.StandardOutput+$javacResult.StandardError) -split '\r?\n' | Where-Object {$_})
      $javaExitCode=$javaResult.ExitCode
      $javacExitCode=$javacResult.ExitCode
      $javaVersionText=$javaOutput -join "`n"
      $javacVersionText=$javacOutput -join "`n"
      $expectedVersion=[string]$package.PackageVersion
      $scenarioStage='Validate java.exe -version output'
      if($javaExitCode -ne 0 -or $javaVersionText -notmatch ('"'+[regex]::Escape($expectedVersion)+'"')){throw "OpenJDK java -version did not report the pinned version $expectedVersion."}
      $scenarioStage='Validate javac.exe -version output'
      if($javacExitCode -ne 0 -or $javacVersionText -notmatch ([regex]::Escape($expectedVersion))){throw "OpenJDK javac -version did not report the pinned version $expectedVersion."}
      $scenarioStage='Compare shared JAVA_HOME, PATH and association state'
      Assert-RideOpenJdkPreservation -Expected $openJdkBaseline -Stage 'installation'
      $scenarioResult.InstallDirectory=$package.InstallDirectory
      $scenarioResult.JavaVersionOutput=$javaOutput
      $scenarioResult.JavacVersionOutput=$javacOutput
      $scenarioResult.Checks=@('RIDEManagedInstall','DedicatedInstallDirectory','JavaRuntimeVersion','JavaCompilerVersion','SharedJavaDefaultsPreserved','RepeatInstall')
    }
    if($scenario.Id -eq 'package.vcredist-v14-x64'){
      $minimum=[version]$package.MinimumInstalledVersion
      $installedVersion=[version]::MinValue
      if(-not [version]::TryParse([string]$installed.DisplayVersion,[ref]$installedVersion) -or $installedVersion -lt $minimum){throw 'RIDE-installed Microsoft Visual C++ runtime registration does not satisfy the declared minimum version.'}
      $runtimeFile=Join-Path (Join-Path $env:SystemRoot 'System32') 'vcomp140.dll'
      if(-not(Test-Path -LiteralPath $runtimeFile -PathType Leaf)){throw 'RIDE-installed Microsoft Visual C++ runtime did not provide vcomp140.dll.'}
      $runtimeFileVersion=[version]::MinValue
      $reportedFileVersion=(Get-Item -LiteralPath $runtimeFile).VersionInfo.FileVersion
      if(-not [version]::TryParse([string]$reportedFileVersion,[ref]$runtimeFileVersion) -or $runtimeFileVersion -lt $minimum){throw 'System32\\vcomp140.dll does not satisfy the declared minimum version.'}
      $scenarioResult.RuntimeFileVersion=$reportedFileVersion
      $scenarioResult.Checks=@('RIDEManagedInstall','MinimumRegisteredVersion','MinimumSystemDllVersion')
    }
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
    Write-RideApplicationProgress -PackageId $scenario.Id -Stage 'Repeat installation'
    $repeat=@(Invoke-RidePlan $plan -Confirm:$false)
    if('No changes were needed; no state record was created.' -notin $repeat){throw 'Repeat installation was not idempotent.'}
    if($Batch -in @(6,7,9,10,11,12)){$scenarioResult.Checks+='RepeatInstall'}
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
    if($userDataFixtures.Count -or $profileFixture -or $scenario.Id -eq 'package.vcredist-v14-x64' -or $Batch -in @(6,7,8,9,10,11,12)){
      $remove=@(Get-RideSingleOperationPlan -Id $scenario.Id -Action Remove -Variant $scenario.Variant)
      $null=Invoke-RidePlan $remove -WhatIf -Confirm:$false
      if(-not(Test-RideDesiredState $plan[0].Operation Present)){throw 'Removal preview changed presence.'}
      if($Batch -in @(6,7,8,9,10,11,12)){$scenarioResult.Checks+='RemovalPreview'}
      $scenarioStage='Run vendor uninstaller'
      Write-RideApplicationProgress -PackageId $scenario.Id -Stage $scenarioStage
      $removeRunId=Get-SavedRunId @(Invoke-RidePlan $remove -Confirm:$false)
      if((Get-RideCurrentState $plan[0].Operation).Present){throw 'Removal did not establish absence.'}
      if($Batch -eq 8 -and ((Test-Path -LiteralPath $javaPath -PathType Leaf) -or (Test-Path -LiteralPath $javacPath -PathType Leaf))){throw 'OpenJDK uninstall left its managed runtime or compiler executable behind.'}
      if($Batch -in @(6,7,8,9,10,11,12)){$scenarioResult.Checks+='RIDERemoval'}
      if($userDataFixtures.Count){Assert-RideApplicationUserDataPreserved -Fixtures $userDataFixtures -Stage 'Vendor uninstall'}elseif($profileFixture -and (-not(Test-Path -LiteralPath $profileFixture) -or [IO.File]::ReadAllText($profileFixture) -cne 'Keep existing profile data.')){throw 'Removal changed existing profile data.'}
      $repeatRemove=@(Invoke-RidePlan $remove -Confirm:$false)
      if('No changes were needed; no state record was created.' -notin $repeatRemove){throw 'Repeat removal was not idempotent.'}
      if($Batch -in @(6,7,8,9,10,11,12)){$scenarioResult.Checks+='RepeatRemoval'}
      $scenarioStage='Recover after vendor uninstall'
      Write-RideApplicationProgress -PackageId $scenario.Id -Stage $scenarioStage
      $null=Restore-RideRun -RunId $removeRunId -Confirm:$false
      if(-not(Test-RideDesiredState $plan[0].Operation Present)){throw 'Compensating removal recovery did not establish presence.'}
      if($Batch -in @(6,7,8,9,10,11,12)){$scenarioResult.Checks+='SavedRemovalRecovery'}
      $scenarioResult.RemovalRecoveryVersion=(Get-RideCurrentState $plan[0].Operation).DisplayVersion
      if($Batch -eq 8){Assert-RideOpenJdkPreservation -Expected $openJdkBaseline -Stage 'removal'}
      if($scenario.Id -eq 'package.vcredist-v14-x64'){
        $scenarioResult.Checks+=@('RepeatInstall','RemovalPreview','RIDERemoval','RepeatRemoval','SavedRemovalRecovery','SavedInstallRecovery')
      }
    }
    $scenarioStage='Restore saved pre-install state'
    Write-RideApplicationProgress -PackageId $scenario.Id -Stage $scenarioStage
    $null=Restore-RideRun -RunId $runId -Confirm:$false
    $restoredOriginal=Get-RideCurrentState $plan[0].Operation
    $preserveNewerRuntime=$false
    if($scenario.Id -eq 'package.vcredist-v14-x64'){
      $priorVersion=[version]::MinValue;$minimumVersion=[version]$package.MinimumInstalledVersion
      $preserveNewerRuntime=[version]::TryParse([string]$before.DisplayVersion,[ref]$priorVersion) -and $priorVersion -lt $minimumVersion
    }
    if($preserveNewerRuntime){
      $restoredVersion=[version]::MinValue
      if(-not $restoredOriginal.Present -or -not [version]::TryParse([string]$restoredOriginal.DisplayVersion,[ref]$restoredVersion) -or $restoredVersion -lt $minimumVersion){throw 'Recovery did not retain the usable shared v14 runtime after an outdated baseline.'}
      $scenarioResult.RecoveryMode='Retained newer shared v14 runtime; exact downgrade is unavailable'
    }elseif($restoredOriginal.Present){throw 'Restoration did not recover original absence.'}
    if($Batch -in @(6,7,9,10,11,12)){$scenarioResult.Checks+='SavedInstallRecovery'}
    if($userDataFixtures.Count){
      Assert-RideApplicationUserDataPreserved -Fixtures $userDataFixtures -Stage 'Saved-state recovery'
      $scenarioResult.UserDataPreservation=$true
      $scenarioResult.Checks+=@('UserDataPreservedAfterInstall','UserDataPreservedAfterVendorUninstall','UserDataPreservedAfterRecovery')
    }elseif($profileFixture){
      if(-not(Test-Path -LiteralPath $profileFixture) -or [IO.File]::ReadAllText($profileFixture) -cne 'Keep existing profile data.'){throw 'Recovery changed existing profile data.'}
      $scenarioResult.ProfilePreservation=$true
    }
    if($Batch -eq 8){Assert-RideOpenJdkPreservation -Expected $openJdkBaseline -Stage 'saved-state recovery'}
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
    if($Batch -eq 8){
      $scenarioResult.FailureStage=$scenarioStage
      $scenarioResult.ExceptionType=$_.Exception.GetType().FullName
      $scenarioResult.ScriptStackTrace=[string]$_.ScriptStackTrace
    }
    if($phoenixMsiLog -and (Test-Path -LiteralPath $phoenixMsiLog -PathType Leaf)){
      $scenarioResult.MsiDiagnostic=[string[]]@(Get-Content -LiteralPath $phoenixMsiLog | Where-Object {$_ -match 'LaunchCondition|Return value 3|\.NET|NetFx|DotNet|Error 1[0-9]{3}'} | Select-Object -Last 60 | ForEach-Object {[string]$_})
    }
    if($scenario.Id -eq 'package.signal'){
      # Bounded product registration evidence; do not export unrelated registry data.
      $scenarioResult.FailureRegistration=@(Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object {$_.DisplayName -like 'Signal*'} | Select-Object -First 8 DisplayName,DisplayVersion,InstallLocation,UninstallString,QuietUninstallString)
    }
    if($scenario.Id -eq 'package.artcraft-launcher'){
      # The pinned per-user MSI records InstallDir in this vendor key. Capture only
      # that marker, its default install directory, matching ARP rows and recent MSI events.
      $launcherDirectory=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs/ArtCraft Launcher'
      $vendorKey='HKCU:\Software\Learning Machines LLC\ArtCraft Launcher'
      $vendorRegistration=$null
      try { $vendorRegistration=Get-ItemProperty -LiteralPath $vendorKey -ErrorAction Stop | Select-Object InstallDir,StartMenuShortcut,DesktopShortcutChoice } catch { }
      $launcherFiles=@()
      if(Test-Path -LiteralPath $launcherDirectory -PathType Container){$launcherFiles=@(Get-ChildItem -LiteralPath $launcherDirectory -File -ErrorAction SilentlyContinue | Select-Object -First 20 Name,Length)}
      $installerEvents=@()
      try { $installerEvents=@(Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='MsiInstaller';StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction Stop | Select-Object -First 12 TimeCreated,Id,Message) } catch { }
      $scenarioResult.FailureRegistration=[ordered]@{
        ExecutionSid=$workerIdentity.User.Value
        Elevated=$workerElevated
        VendorRegistryKey=$vendorKey
        VendorRegistration=$vendorRegistration
        DefaultInstallDirectory=$launcherDirectory
        DefaultInstallDirectoryExists=(Test-Path -LiteralPath $launcherDirectory -PathType Container)
        DefaultInstallFiles=$launcherFiles
        MatchingUninstallEntries=@(Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -match 'ArtCraft|Craft Launcher'} | Select-Object -First 8 DisplayName,DisplayVersion,InstallLocation,UninstallString,QuietUninstallString)
        RecentMsiInstallerEvents=$installerEvents
      }
    }
    if($Batch -eq 8){
      # RIDE presence detection failed after the pinned MSI returned. Capture only
      # matching machine uninstall records and the declared install directory.
      $openJdkRoots=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
      $openJdkRegistrations=@(foreach($root in $openJdkRoots){
        Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
          Where-Object {$_.DisplayName -match 'OpenJDK'} |
          Select-Object -First 12 DisplayName,DisplayVersion,Publisher,InstallLocation,InstallSource,UninstallString
      })
      $openJdkDirectory=[string]$package.InstallDirectory
      $openJdkFiles=@()
      if(Test-Path -LiteralPath $openJdkDirectory -PathType Container){
        $openJdkFiles=@(Get-ChildItem -LiteralPath $openJdkDirectory -File -ErrorAction SilentlyContinue | Select-Object -First 12 Name,Length)
      }
      $installerEvents=@()
      try {
        $installerEvents=@(Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='MsiInstaller';StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction Stop |
          Where-Object {$_.Message -match 'OpenJDK|Microsoft JDK'} |
          Select-Object -First 12 TimeCreated,Id,Message)
      } catch { }
      $scenarioResult.FailureRegistration=[ordered]@{
        ExecutionSid=$workerIdentity.User.Value
        Elevated=$workerElevated
        ExpectedDisplayNamePattern=[string]$package.DisplayNamePattern
        DeclaredInstallDirectory=$openJdkDirectory
        InstallDirectoryExists=(Test-Path -LiteralPath $openJdkDirectory -PathType Container)
        JavaExecutableExists=(Test-Path -LiteralPath (Join-Path $openJdkDirectory 'bin/java.exe') -PathType Leaf)
        JavacExecutableExists=(Test-Path -LiteralPath (Join-Path $openJdkDirectory 'bin/javac.exe') -PathType Leaf)
        InstallDirectoryFiles=$openJdkFiles
        MatchingUninstallEntries=$openJdkRegistrations
        RecentMsiInstallerEvents=$installerEvents
      }
    }
    Write-Warning "$($scenario.Id): $($scenarioResult.Error)"
  }
  Add-RideApplicationBatchResult -Results $results -JsonRecords $jsonResults -Result ([pscustomobject]$scenarioResult) -EvidencePath $evidencePath
}
$results | Format-Table Id,Variant,Target,Status,Version -AutoSize
if(@($results | Where-Object { $_.Status -notin @('Passed','NotApplicable') }).Count){throw "Applications batch $Batch has failed scenarios; see application evidence."}
