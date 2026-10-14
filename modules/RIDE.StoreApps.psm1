<#
.SYNOPSIS
  Inspect and manage explicitly selected current-user Store registrations.
.DESCRIPTION
  Uses catalog identities and ordered groups. Captures per-app removal intent,
  reports partial completion and offers only retained-payload re-registration.
  Downloads, provisioning, AllUsers changes and policy writes are forbidden.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Applicable accepted target and the unelevated current desktop user.
  State: LocalApplicationData/RIDE/State/StoreApps, owned by the execution user.
  Recovery: Best effort retained-payload registration; no app-data/version guarantee.
  Owner: RIDE-Windows maintainers. Version: 0.3.1.
  Changelog: 0.3.1: Refuse unverified/conflicting runtime identity/type evidence.
    0.3.0: Apply reviewed identity/removability rule; report unknown system flags.
    0.2.0: Add source-bound same-session desktop-user Store handoff.
    0.1.2: Query documented client management registration instead of
    interpreting generic enrollment keys as active MDM; Server proof stays pending.
    0.1.1: Inspect current-user runtime type/stub/signature evidence;
    keep unavailable system flags unknown and separate bundle removal from main source.
    0.1.0: Add guarded consumer-app planning, removal and source-bound recovery.
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1') -ErrorAction Stop

function Get-RideStoreSelection {
  param([string]$Id)
  $catalog=Import-RideCatalogData -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
  $group=@($catalog.Groups|Where-Object {$_.Id -ieq $Id -and $_.Workflow -eq 'StoreApps'})
  $ids=if($group.Count -eq 1){@($group[0].Members)}else{@($Id)}
  if($ids.Count -lt 1 -or $ids.Count -gt 32 -or @($ids|Sort-Object -Unique).Count -ne $ids.Count){throw 'Invalid Store app selection.'}
  foreach($key in $ids){
    $matches=@($catalog.Operations|Where-Object {$_.Id -ieq $key -and $_.Kind -eq 'StoreApp'})
    if($matches.Count -ne 1){throw "Unknown Store app or Store group ID: $key"}
    $matches[0]
  }
}

function Get-RideStoreIdentity {
  $i=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{[pscustomobject]@{Sid=$i.User.Value;Elevated=([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}}finally{$i.Dispose()}
}

function Get-RideStoreDesktop {
  $m=Import-Module (Join-Path $PSScriptRoot 'RIDE.UserHandoff.psm1') -Force -PassThru -Scope Local
  & $m {Get-RideDesktopHandoffContext}
}

function Get-RideStoreTarget {
  $v=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $p=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -ErrorAction Stop
  if($p.ProductType -eq 'WinNT' -and [int]$v.CurrentBuildNumber -ge 22000){return 'Windows 11'}
  if($p.ProductType -ne 'WinNT' -and [int]$v.CurrentBuildNumber -ge 26100){return 'Windows Server 2025'}
  'Unsupported Windows target'
}

function Get-RideStoreNativePackages {
  param([hashtable]$Operation)
  @(Get-AppxPackage -Name $Operation.AppxName -PackageTypeFilter Main,Bundle,Resource,Framework,Optional -ErrorAction Stop)
}

function Get-RideStoreRegisteredPackages {
  $packages=@(Get-AppxPackage -PackageTypeFilter Main,Bundle,Resource,Framework,Optional -ErrorAction Stop)
  if($packages.Count -gt 5000){throw 'Current-user dependency inspection exceeds its bound.'}
  $packages
}

function Get-RideStoreRuntimePackage {
  param([string]$Sid,[string]$FullName)
  if($PSVersionTable.PSVersion.Major -ne 5){throw 'Windows Runtime inspection requires native Windows PowerShell 5.1.'}
  $manager=[Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime]::new()
  $package=$manager.FindPackageForUser($Sid,$FullName)
  if(-not $package -or $package.Id.FullName -cne $FullName){throw 'Current-user runtime package identity unavailable.'}
  [pscustomobject]@{Name=$package.Id.Name;Family=$package.Id.FamilyName;FullName=$package.Id.FullName;IsFramework=$package.IsFramework;IsResourcePackage=$package.IsResourcePackage;IsBundle=$package.IsBundle;IsStub=$package.IsStub;SignatureKind=[string]$package.SignatureKind}
}

function Get-RideStoreAppState {
  <#
  .SYNOPSIS
    Inspect one exact catalog identity for the execution user without changing state.
  .PARAMETER Operation
    StoreApp catalog metadata.
  .EXAMPLE
    Get-Help Get-RideStoreAppState -Full
  .OUTPUTS
    PSCustomObject. Exact registrations and nullable protection flags.
  .NOTES
    Version 0.1.0; no AllUsers query or acquisition.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable]$Operation)
  if($Operation.Kind -ne 'StoreApp' -or $Operation.Scope -ne 'User' -or $Operation.AppxName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]+$' -or $Operation.PackageFamilyName -notmatch '^[a-zA-Z0-9.-]+_[a-z0-9]{13}$'){throw 'Invalid Store app metadata.'}
  $identity=Get-RideStoreIdentity
  $packages=@(Get-RideStoreNativePackages $Operation)
  if($packages.Count -gt 64){throw 'Store registration inspection exceeds its bound.'}
  $rows=@(foreach($p in ($packages|Sort-Object PackageFullName)){
    if($p.Name -ine $Operation.AppxName -or -not $p.PackageFullName -or -not $p.PackageFamilyName){throw 'Provider returned an unexpected Store identity.'}
    $row=[ordered]@{Name=[string]$p.Name;Family=[string]$p.PackageFamilyName;FullName=[string]$p.PackageFullName;Version=[string]$p.Version;Publisher=[string]$p.Publisher;Status=[string]$p.Status;InstallLocation=[string]$p.InstallLocation;Dependencies=@($p.Dependencies|ForEach-Object {[string]$_.PackageFullName})}
    foreach($flag in @('IsFramework','IsResourcePackage','NonRemovable','IsPartOfSystem','IsBundle','IsStub')){$row[$flag]=if($p.$flag -is [bool]){$p.$flag}else{$null}}
    $row.SystemProtectionObservation=if($null -eq $row.IsPartOfSystem){'Unknown'}elseif($row.IsPartOfSystem){'System'}else{'Not marked system'}
    $row.RuntimeVerified=$false;$row.RuntimeError=$null;$row.SignatureKind=$null
    try{
      $runtime=Get-RideStoreRuntimePackage -Sid $identity.Sid -FullName $p.PackageFullName
      if($runtime.Name -cne $p.Name -or $runtime.Family -cne $p.PackageFamilyName -or $runtime.FullName -cne $p.PackageFullName){throw 'Runtime/Appx identity mismatch.'}
      $verifiedTypes=@{}
      foreach($flag in @('IsFramework','IsResourcePackage','IsBundle','IsStub')){
        if($runtime.$flag -isnot [bool]){throw 'Runtime type evidence unavailable.'}
        if($null -ne $row[$flag] -and $row[$flag] -ne $runtime.$flag){throw 'Runtime/Appx type drift.'}
        $verifiedTypes[$flag]=$runtime.$flag
      }
      foreach($flag in $verifiedTypes.Keys){$row[$flag]=$verifiedTypes[$flag]}
      $row.SignatureKind=$runtime.SignatureKind;$row.RuntimeVerified=$true
      # Signature category is not a system-protection flag. Never synthesize
      # IsPartOfSystem=false from a Store certificate.
    }catch{$row.RuntimeError=$_.Exception.Message}
    [pscustomobject]$row
  })
  [pscustomobject]@{SnapshotVersion=1;OperationId=$Operation.Id;UserSid=$identity.Sid;Present=($rows.Count -gt 0);Packages=$rows;ExactRecovery=$false;DisplayName=$Operation.Name;DisplayVersion=(@($rows.Version|Sort-Object -Unique) -join ', ')}
}

function Get-RideStorePolicyGuard {
  param([hashtable]$Operation)
  # Refuse managed devices rather than assuming a local registry view is effective policy.
  $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  if($computer.PartOfDomain -isnot [bool] -or $computer.PartOfDomain){return 'Managed or unknown domain policy source'}
  if((Get-RideStoreTarget) -eq 'Windows 11'){
    if(Get-RideStoreManagementRegistration){return 'Device is MDM registered; effective management policy requires separate review'}
    $joinPaths=@('HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo')
  }else{
    # The documented management-registration API has no supported Server target.
    $joinPaths=@('HKLM:\SOFTWARE\Microsoft\Enrollments','HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo')
  }
  foreach($path in $joinPaths){
    if(Test-Path -LiteralPath $path -ErrorAction Stop){
      if(@(Get-ChildItem -LiteralPath $path -ErrorAction Stop).Count){return 'Managed or unknown enrollment policy source'}
    }
  }
  $root='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages'
  if(-not(Test-Path -LiteralPath $root -ErrorAction Stop)){return $null}
  $key=Get-Item -LiteralPath $root -ErrorAction Stop
  try{
    if('Enabled' -notin $key.GetValueNames()){return 'Removal policy definition incomplete'}
    if($key.GetValueKind('Enabled').ToString() -ne 'DWord' -or $key.GetValue('Enabled') -notin @(0,1)){return 'Removal policy enablement unknown'}
    # A configured removal policy requires separate effective-policy acceptance,
    # even if this particular app's local selection appears unselected.
    if($key.GetValue('Enabled') -eq 1){return 'Active device removal policy; use the separate policy workflow'}
  }finally{$key.Dispose()}
  $null
}

function Get-RideStoreManagementRegistration {
  if(-not ('Ride.StoreManagementObservationV1' -as [type])){
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Ride {
 public static class StoreManagementObservationV1 {
  [DllImport("MDMRegistration.dll", ExactSpelling=true)]
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  static extern int IsDeviceRegisteredWithManagement([MarshalAs(UnmanagedType.Bool)] out bool registered, uint length, IntPtr upn);
  public static bool Read() {
   bool registered;
   int result=IsDeviceRegisteredWithManagement(out registered,0,IntPtr.Zero);
   if(result!=0) throw new InvalidOperationException("Management registration query failed: 0x"+result.ToString("X8"));
   return registered;
  }
 }
}
'@
  }
  [Ride.StoreManagementObservationV1]::Read()
}

function Get-RideStoreStateRoot {Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RIDE/State/StoreApps'}

function Assert-RideStorePath {
  param([string]$Path,[string]$Root)
  $full=[IO.Path]::GetFullPath($Path);$base=[IO.Path]::GetFullPath($Root).TrimEnd('\','/')
  if(-not $full.StartsWith($base+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Store path escapes its declared root.'}
  $cursor=$full
  while($cursor){
    if(Test-Path -LiteralPath $cursor){if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Store paths must not traverse reparse points.'}}
    $parent=Split-Path -Parent $cursor
    if($parent -eq $cursor){break};$cursor=$parent
  }
  $full
}

function Get-RideStoreManifestProof {
  param($Package)
  if($Package.IsStub -ne $false){throw 'A verified full payload is required; stub/unknown acquisition routes are forbidden.'}
  $root=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WindowsApps'
  $path=Assert-RideStorePath -Path (Join-Path $Package.InstallLocation 'AppxManifest.xml') -Root $root
  if(-not(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -gt 1048576){throw 'Retained manifest source unavailable or oversized.'}
  $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
  $reader=[Xml.XmlReader]::Create($path,$settings)
  try{$xml=[Xml.XmlDocument]::new();$xml.XmlResolver=$null;$xml.Load($reader)}finally{$reader.Dispose()}
  $entry=$xml.DocumentElement.SelectSingleNode('*[local-name()="Identity"]')
  if(-not $entry -or $entry.GetAttribute('Name') -cne $Package.Name -or $entry.GetAttribute('Publisher') -cne $Package.Publisher -or $entry.GetAttribute('Version') -cne $Package.Version){throw 'Retained manifest identity/version/publisher mismatch.'}
  [pscustomobject]@{Path=$path;SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;Name=$Package.Name;Publisher=$Package.Publisher;Version=$Package.Version;Dependencies=@($Package.Dependencies)}
}

function Read-RideStoreRemovalRun {
  param([string]$RunId,[string]$ExpectedUserSid)
  if($RunId -notmatch '^[0-9a-f]{32}$'){throw 'Reinstall requires a saved Store removal RunId.'}
  $root=Get-RideStoreStateRoot
  $path=Assert-RideStorePath -Path (Join-Path $root "$RunId/manifest.json") -Root $root
  if((Get-Item -LiteralPath $path).Length -gt 1048576){throw 'Saved Store manifest exceeds its bound.'}
  $data=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
  if($data.SchemaVersion -ne 1 -or $data.Workflow -cne 'StoreApps' -or $data.RunId -cne $RunId -or $data.Action -cne 'Uninstall' -or $data.UserSid -cne $ExpectedUserSid -or @($data.Items).Count -lt 1 -or @($data.Items).Count -gt 32 -or @($data.Items.OperationId|Sort-Object -Unique).Count -ne @($data.Items).Count){throw 'Invalid Store removal record or different user owner.'}
  $data
}

function Get-RideStoreAppPlan {
  <#
  .SYNOPSIS
    Plan explicit Store app/group uninstall or retained-source reinstall.
  .PARAMETER Id
    Store app or Store group ID from catalog/operations.psd1.
  .PARAMETER Action
    Uninstall or Reinstall; this never changes device policy or downloads payloads.
  .PARAMETER ExpectedUserSid
    Explicit intended execution/desktop SID; mismatches fail before Appx inspection.
  .PARAMETER RemovalRunId
    Saved removal run required for reinstall source inspection.
  .EXAMPLE
    Get-RideStoreAppPlan -Id solution.store-consumer-apps -Action Uninstall -ExpectedUserSid S-1-5-21-1-2-3-1001
  .OUTPUTS
    PSCustomObject. Per-app live evidence, refusal reasons and source information.
  .NOTES
    Version 0.3.0. Planning is read-only. Reviewed catalog identities require known
    removability/type/stub evidence. Unknown IsPartOfSystem remains visible;
    a known system/protected flag still refuses the action.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Id,[Parameter(Mandatory)][ValidateSet('Uninstall','Reinstall')][string]$Action,[Parameter(Mandatory)][ValidatePattern('^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$')][string]$ExpectedUserSid,[string]$RemovalRunId)
  if((Get-RideStoreIdentity).Sid -cne $ExpectedUserSid){throw 'Store intended-user SID mismatch; nothing inspected or changed.'}
  $operations=@(Get-RideStoreSelection $Id)
  if($Action -eq 'Uninstall'){[array]::Reverse($operations)}
  $saved=if($Action -eq 'Reinstall'){Read-RideStoreRemovalRun $RemovalRunId $ExpectedUserSid}else{$null}
  $target=Get-RideStoreTarget
  foreach($operation in $operations){
    $before=Get-RideStoreAppState $operation
    $reasons=[Collections.Generic.List[string]]::new();$source=$null
    if($operation.ProtectionRule -cne 'ReviewedIdentityRemovabilityV1' -or $operation.RequireKnownProtectionFlags -ne $true){$reasons.Add('Reviewed identity/removability rule required')}
    if($target -notin $operation.SupportedTargets){$reasons.Add('Target acceptance pending or unsupported')}
    try{
      $desktop=Get-RideStoreDesktop
      if($desktop.CurrentSid -cne $ExpectedUserSid -or $desktop.TargetSid -cne $ExpectedUserSid -or $desktop.CurrentElevated -or $desktop.ShellElevated -or $desktop.SessionId -le 0 -or $desktop.SessionId -ne $desktop.CurrentSessionId -or $desktop.ShellProcessId -le 0){$reasons.Add('Use the unelevated intended user in the current desktop session')}
    }catch{$reasons.Add('Current desktop identity unavailable')}
    try{$policy=Get-RideStorePolicyGuard $operation;if($policy){$reasons.Add($policy)}}catch{$reasons.Add('Device policy source unavailable; no app change allowed')}
    $primary=@($before.Packages|Where-Object {$_.IsResourcePackage -eq $false -and $_.IsFramework -eq $false})
    $bundles=@($primary|Where-Object IsBundle -eq $true)
    $sourcePrimary=@($primary|Where-Object IsBundle -eq $false)
    if($bundles.Count -eq 1){$primary=$bundles}
    if($before.Present){
      if(@($before.Packages|Where-Object {$_.Family -ine $operation.PackageFamilyName -or $_.Name -ine $operation.AppxName}).Count){$reasons.Add('Unexpected publisher family or app identity')}
      foreach($p in $before.Packages){
        if($p.NonRemovable -eq $true -or $p.IsPartOfSystem -eq $true -or $p.IsFramework -eq $true){$reasons.Add('Protected/system/framework registration');break}
        if($null -eq $p.NonRemovable -or $null -eq $p.IsResourcePackage -or $null -eq $p.IsFramework -or $null -eq $p.IsBundle -or $null -eq $p.IsStub){$reasons.Add('Protection/type flags incomplete');break}
        if($p.RuntimeVerified -ne $true){$reasons.Add('Runtime package identity/type evidence unavailable or conflicting');break}
        if($p.IsStub){$reasons.Add('Stub package source requires separate acquisition review');break}
      }
      if($primary.Count -ne 1){$reasons.Add('Ambiguous or missing primary registration')}
      if(@($before.Packages|Where-Object Status -ne 'Ok').Count){$reasons.Add('Registration status is not Ok')}
    }
    if($Action -eq 'Uninstall' -and $before.Present){
      if($sourcePrimary.Count -ne 1){$reasons.Add('Retained main-payload source ambiguous or unavailable')}
      else{try{$source=Get-RideStoreManifestProof $sourcePrimary[0]}catch{$reasons.Add('Retained-payload capture unavailable')}}
    }
    if($Action -eq 'Uninstall' -and $before.Present){
      try{
        $consumers=@(Get-RideStoreRegisteredPackages|Where-Object {$_.Name -ine $operation.AppxName -and @($_.Dependencies|Where-Object {$_.PackageFullName -in $before.Packages.FullName}).Count})
        if($consumers.Count){$reasons.Add('Other registered apps depend on this app; review consumers separately')}
      }catch{$reasons.Add('Current-user consumer dependencies unavailable')}
    }
    if($Action -eq 'Reinstall' -and -not $before.Present){
      $prior=@($saved.Items|Where-Object OperationId -eq $operation.Id)
      if($prior.Count -ne 1 -or $prior[0].Status -notin @('Intent','Failed','Completed') -or $prior[0].Before.UserSid -cne $ExpectedUserSid -or -not $prior[0].Before.Present -or $prior[0].Family -ine $operation.PackageFamilyName -or -not $prior[0].Source){$reasons.Add('No owned removal intent/source')}
      else{
        try{
          $s=$prior[0].Source
          $captured=@($prior[0].Before.Packages|Where-Object {$_.Family -ieq $operation.PackageFamilyName -and $_.Name -ieq $operation.AppxName -and $_.Publisher -ceq $s.Publisher -and $_.Version -ceq $s.Version -and (Join-Path $_.InstallLocation 'AppxManifest.xml') -ceq $s.Path})
          if($captured.Count -ne 1 -or $captured[0].IsStub -ne $false -or $s.Name -cne $operation.AppxName -or $s.SHA256 -notmatch '^[a-fA-F0-9]{64}$' -or @($s.Dependencies).Count -gt 256){throw 'Saved source does not match captured full-payload identity'}
          $proof=Get-RideStoreManifestProof ([pscustomobject]@{InstallLocation=(Split-Path -Parent $s.Path);Name=$operation.AppxName;Publisher=$s.Publisher;Version=$s.Version;Dependencies=@($s.Dependencies);IsStub=$false})
          if($proof.SHA256 -cne $s.SHA256){throw 'Retained manifest changed'}
          $source=$proof
          $available=@(Get-RideStoreRegisteredPackages|ForEach-Object PackageFullName)
          if(@($proof.Dependencies|Where-Object {$_ -notin $available}).Count){throw 'Retained dependencies unavailable'}
        }catch{$reasons.Add('Source unavailable or changed; acquisition remains paused')}
      }
    }
    [pscustomobject]@{Operation=$operation;Action=$Action;ExpectedUserSid=$ExpectedUserSid;RemovalRunId=$RemovalRunId;Before=$before;Source=$source;Primary=$(if($primary.Count -eq 1){$primary[0]}else{$null});Refusals=@($reasons|Sort-Object -Unique);Target=$target;DesiredPresence=($Action -eq 'Reinstall');Recovery='BestEffortRetainedPayload; app data and prior version not guaranteed'}
  }
}

function Save-RideStoreRun {
  param($Record)
  $root=Get-RideStoreStateRoot;$directory=Assert-RideStorePath -Path (Join-Path $root $Record.RunId) -Root $root
  $null=New-Item -ItemType Directory -Path $directory -Force
  $path=Join-Path $directory 'manifest.json';$temp=Join-Path $directory 'manifest.tmp'
  $null=Assert-RideStorePath -Path $path -Root $root
  $null=Assert-RideStorePath -Path $temp -Root $root
  [IO.File]::WriteAllText($temp,($Record|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
  Move-Item -LiteralPath $temp -Destination $path -Force
}

function Invoke-RideStoreNativeRemove {param([string]$FullName) Remove-AppxPackage -Package $FullName -ErrorAction Stop}
function Invoke-RideStoreNativeRegister {param([string]$Path) Add-AppxPackage -Register $Path -DisableDevelopmentMode -ErrorAction Stop}

function Invoke-RideStoreAppAction {
  <#
  .SYNOPSIS
    Apply a fresh guarded Store plan with per-app intent and partial results.
  .PARAMETER Id
    Exact Store app/group ID from the catalog.
  .PARAMETER Action
    Uninstall or retained-payload Reinstall, independent from policy.
  .PARAMETER ExpectedUserSid
    Explicit intended user's SID; actual desktop and unelevated identity must match.
  .PARAMETER RemovalRunId
    Owned removal record for Reinstall.
  .EXAMPLE
    Invoke-RideStoreAppAction -Id solution.store-consumer-apps -Action Uninstall -ExpectedUserSid S-1-5-21-1-2-3-1001 -WhatIf
  .OUTPUTS
    PSCustomObject. Completed, already matching, refused, preview or failed per-app results.
  .NOTES
    Version 0.1.0. Intent is saved before mutation. No exact recovery, acquisition,
    provisioning or policy change; absent apps and preview create no state records.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$Id,[Parameter(Mandatory)][ValidateSet('Uninstall','Reinstall')][string]$Action,[Parameter(Mandatory)][ValidatePattern('^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$')][string]$ExpectedUserSid,[string]$RemovalRunId)
  $arguments=@{Id=$Id;Action=$Action;ExpectedUserSid=$ExpectedUserSid;RemovalRunId=$RemovalRunId}
  $plan=@(Get-RideStoreAppPlan @arguments)
  $run=[ordered]@{SchemaVersion=1;Workflow='StoreApps';RunId=[guid]::NewGuid().ToString('N');UserSid=$ExpectedUserSid;Action=$Action;RemovalRunId=$RemovalRunId;StartedAtUtc=[DateTime]::UtcNow.ToString('o');Status='InProgress';ExactRecovery=$false;Items=@($plan|ForEach-Object {[ordered]@{OperationId=$_.Operation.Id;Family=$_.Operation.PackageFamilyName;Before=$_.Before;Source=$_.Source;Status='Planned';Error=$null;After=$null}})}
  $persisted=$false
  $results=[Collections.Generic.List[object]]::new()
  foreach($item in $plan){
    $status='Refused';$error=$null
    $row=@($run.Items|Where-Object {$_.OperationId -eq $item.Operation.Id})[0]
    $intentSaved=$false
    $systemNote=if(@($item.Before.Packages|Where-Object {$null -eq $_.IsPartOfSystem}).Count){'; IsPartOfSystem=Unknown'}else{''}
    if($item.Refusals.Count){$error=$item.Refusals -join '; '}
    elseif($item.Before.Present -eq $item.DesiredPresence){$status='AlreadyMatching'}
    elseif(-not $PSCmdlet.ShouldProcess("$($item.Operation.Name) for $ExpectedUserSid", "$Action registration; local data/prior version recovery not guaranteed$systemNote")){$status='NotApplied'}
    else{
      try{
        # Repeat all identity, policy, source and registration checks after confirmation.
        $fresh=@(Get-RideStoreAppPlan -Id $item.Operation.Id -Action $Action -ExpectedUserSid $ExpectedUserSid -RemovalRunId $RemovalRunId)[0]
        if($fresh.Refusals.Count){throw ($fresh.Refusals -join '; ')}
        if(($fresh.Before.Packages|ConvertTo-Json -Depth 8 -Compress) -cne ($item.Before.Packages|ConvertTo-Json -Depth 8 -Compress)){throw 'Registration/protection drift; replan before mutation'}
        if($item.Source -and ($fresh.Source.Path -cne $item.Source.Path -or $fresh.Source.SHA256 -cne $item.Source.SHA256)){throw 'Retained source drift; no mutation'}
        $row.Before=$fresh.Before;$row.Source=$fresh.Source;$row.Status='Intent'
        Save-RideStoreRun $run;$persisted=$true;$intentSaved=$true
        if($Action -eq 'Uninstall'){Invoke-RideStoreNativeRemove $fresh.Primary.FullName}else{Invoke-RideStoreNativeRegister $fresh.Source.Path}
        $after=Get-RideStoreAppState $item.Operation;$row.After=$after
        if($after.Present -ne $item.DesiredPresence -or @($after.Packages|Where-Object {$_.Family -ine $item.Operation.PackageFamilyName}).Count){throw 'Native registration readback did not match the declared identity/presence'}
        $row.Status='Completed';Save-RideStoreRun $run;$status='Completed'
      }catch{
        $status='Failed';$error=$_.Exception.Message
        if($intentSaved){$row.Status='Failed';$row.Error=$error;try{$row.After=Get-RideStoreAppState $item.Operation;Save-RideStoreRun $run}catch{$error+='; state/evidence persistence failed: '+$_.Exception.Message}}
      }
    }
    $row.Status=$status;$row.Error=$error
    $results.Add([pscustomobject]@{OperationId=$item.Operation.Id;Action=$Action;Status=$status;Error=$error;RunId=$null;RecordCreated=$false;UserSid=$ExpectedUserSid;ExactRecovery=$false})
  }
  if($persisted){
    $run.Status=if(@($run.Items|Where-Object {$_.Status -notin @('Completed','AlreadyMatching')}).Count){'Partial'}else{'Completed'}
    $run['FinishedAtUtc']=[DateTime]::UtcNow.ToString('o')
    try{Save-RideStoreRun $run}catch{throw "Store final state persistence failed. Run ID: $($run.RunId). Retain prior intent/partial evidence. $($_.Exception.Message)"}
  }
  foreach($result in $results){if($persisted){$result.RunId=$run.RunId;$result.RecordCreated=$true};$result}
}

function Get-RideStoreHandoffSourceHash {
  $m=Import-Module (Join-Path $PSScriptRoot 'RIDE.UserHandoff.psm1') -Force -PassThru -Scope Local
  & $m {Get-RideHandoffSourceHash}
}

function Start-RideStoreShellProcess {
  param($Context,[string]$Arguments)
  $m=Import-Module (Join-Path $PSScriptRoot 'RIDE.UserHandoff.psm1') -Force -PassThru -Scope Local
  & $m {param($context,$arguments) Start-RideHandoffShellProcess $context $arguments} $Context $Arguments
}

function Start-RideStoreDesktopHandoff {
  <#
  .SYNOPSIS
    Launch an explicit Store action as the signed-in user in this desktop session.
  .DESCRIPTION
    Parent reads selection/source metadata only; child owns live queries and records.
    A launch receipt is not completion. No credentials, UAC change or cross-session route.
  .PARAMETER Command
    Plan, Uninstall or Reinstall, separate from settings and device policy.
  .PARAMETER Id
    Store app/group ID from the built-in catalog.
  .PARAMETER ExpectedUserSid
    Must match the existing unelevated shell's SID in the caller's current session.
  .PARAMETER RemovalRunId
    Explicit saved Store removal ID for Reinstall, read only by the desktop child.
  .PARAMETER Action
    Uninstall or Reinstall for Plan; other commands derive their action.
  .EXAMPLE
    Start-RideStoreDesktopHandoff Plan solution.store-consumer-apps -ExpectedUserSid S-1-5-21-1-2-3-1001 -WhatIf
  .OUTPUTS
    PSCustomObject. Preview/launch receipt; actual results are in the user window.
  .NOTES
    Version 0.2.0. Source, SID, session and shell identity are revalidated in the child.
    Interactive native handoff acceptance remains pending.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidateSet('Plan','Uninstall','Reinstall')][string]$Command,[Parameter(Mandatory)][string]$Id,[Parameter(Mandatory)][ValidatePattern('^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$')][string]$ExpectedUserSid,[string]$RemovalRunId,[ValidateSet('Uninstall','Reinstall')][string]$Action='Uninstall')
  $context=Get-RideStoreDesktop
  if($context.TargetSid -cne $ExpectedUserSid -or $context.ShellElevated -or $context.SessionId -le 0 -or $context.SessionId -ne $context.CurrentSessionId -or $context.ShellProcessId -le 0){throw 'Store handoff requires the expected unelevated desktop user in this current session.'}
  $null=@(Get-RideStoreSelection $Id)
  $effective=if($Command -eq 'Plan'){$Action}else{$Command}
  if($effective -eq 'Reinstall' -and $RemovalRunId -notmatch '^[0-9a-f]{32}$'){throw 'Desktop reinstall requires an explicit Store removal RunId.'}
  if($effective -eq 'Uninstall' -and $RemovalRunId){throw 'Desktop uninstall uses no prior removal record.'}
  $request=[ordered]@{SchemaVersion=1;Workflow='StoreDesktopHandoff';RequestId=[guid]::NewGuid().ToString('N');Root=(Split-Path -Parent $PSScriptRoot);SourceHash=Get-RideStoreHandoffSourceHash;TargetSid=$ExpectedUserSid;SessionId=$context.SessionId;ShellProcessId=$context.ShellProcessId;Command=$Command;Id=$Id;Action=$effective;RemovalRunId=$RemovalRunId}
  $data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Depth 5 -Compress)))
  $bootstrap=@'
$ErrorActionPreference='Stop'
try {
 $r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUEST__'))|ConvertFrom-Json
 $i=[Security.Principal.WindowsIdentity]::GetCurrent()
 try {
  if($i.User.Value -cne $r.TargetSid -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne $r.SessionId -or ([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Store child identity/session/elevation mismatch; nothing applied.'}
 }finally{$i.Dispose()}
 Import-Module (Join-Path $r.Root 'modules/RIDE.StoreApps.psm1') -Force
 Invoke-RideStoreDesktopRequest -Request $r
}catch{Write-Error -ErrorRecord $_ -ErrorAction Continue}
'@
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap.Replace('__REQUEST__',$data)))
  $arguments='-NoProfile -NoExit -EncodedCommand '+$encoded
  if($arguments.Length -gt 30000){throw 'Store handoff command exceeds its size bound.'}
  $launched=$false
  if($PSCmdlet.ShouldProcess("$ExpectedUserSid, session $($context.SessionId)","Launch desktop Store $Command for $Id; child displays live plan and actual results")){
    Start-RideStoreShellProcess $context $arguments;$launched=$true
  }
  [pscustomobject]@{Status=$(if($launched){'Launched'}else{'NotLaunched'});RequestId=$request.RequestId;TargetSid=$ExpectedUserSid;SessionId=$context.SessionId;SelectionId=$Id;CompletionVerified=$false;Recovery='Read actual Store results/removal IDs in the desktop user window'}
}

function Invoke-RideStoreDesktopRequest {
  <#
  .SYNOPSIS
    Revalidate and execute an explicit Store request in the desktop user's process.
  .PARAMETER Request
    Bounded source-bound data emitted by Start-RideStoreDesktopHandoff.
  .EXAMPLE
    Get-Help Invoke-RideStoreDesktopRequest -Full
  .OUTPUTS
    PSCustomObject. Live plans and per-app results in the desktop user context.
  .NOTES
    Version 0.3.0. Display unknown system protection explicitly before app confirmation.
    No mixed scope, machine policy, source acquisition or hidden fallback.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Request)
  $keys=@('SchemaVersion','Workflow','RequestId','Root','SourceHash','TargetSid','SessionId','ShellProcessId','Command','Id','Action','RemovalRunId')
  $actualKeys=@($Request.PSObject.Properties.Name)
  if($actualKeys.Count -ne $keys.Count -or @($actualKeys|Where-Object {$_ -notin $keys}).Count -or $Request.SchemaVersion -ne 1 -or $Request.Workflow -cne 'StoreDesktopHandoff' -or $Request.RequestId -notmatch '^[0-9a-f]{32}$' -or $Request.SourceHash -notmatch '^[A-Fa-f0-9]{64}$' -or $Request.Command -notin @('Plan','Uninstall','Reinstall') -or $Request.Action -notin @('Uninstall','Reinstall') -or [IO.Path]::GetFullPath($Request.Root) -cne [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))){throw 'Invalid Store desktop request.'}
  if($Request.Command -ne 'Plan' -and $Request.Action -cne $Request.Command){throw 'Store desktop command/action mismatch.'}
  $identity=Get-RideStoreIdentity;$desktop=Get-RideStoreDesktop
  if($identity.Sid -cne $Request.TargetSid -or $identity.Elevated -or $desktop.TargetSid -cne $Request.TargetSid -or $desktop.CurrentSid -cne $Request.TargetSid -or $desktop.CurrentElevated -or $desktop.ShellElevated -or $desktop.SessionId -le 0 -or $desktop.SessionId -ne $Request.SessionId -or $desktop.CurrentSessionId -ne $Request.SessionId -or $desktop.ShellProcessId -ne $Request.ShellProcessId){throw 'Store desktop owner/session/shell changed; nothing inspected or applied.'}
  if((Get-RideStoreHandoffSourceHash) -cne $Request.SourceHash){throw 'Store desktop source changed; replan before launch.'}
  $parameters=@{Id=[string]$Request.Id;Action=[string]$Request.Action;ExpectedUserSid=[string]$Request.TargetSid;RemovalRunId=[string]$Request.RemovalRunId}
  $plan=@(Get-RideStoreAppPlan @parameters)
  $plan|Select-Object @{Name='OperationId';Expression={$_.Operation.Id}},Action,@{Name='ProtectionRule';Expression={$_.Operation.ProtectionRule}},@{Name='UnknownSystemProtection';Expression={@($_.Before.Packages|Where-Object {$null -eq $_.IsPartOfSystem}|ForEach-Object FullName)}},Refusals,Recovery
  if($Request.Command -ne 'Plan'){
    # The child offers its own concrete per-app confirmation after live inspection.
    Invoke-RideStoreAppAction @parameters -Confirm
  }
}

Export-ModuleMember -Function Get-RideStoreAppState,Get-RideStoreAppPlan,Invoke-RideStoreAppAction,Start-RideStoreDesktopHandoff,Invoke-RideStoreDesktopRequest
