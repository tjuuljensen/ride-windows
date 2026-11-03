<#
.SYNOPSIS
  Create and remove owned disposable users for first-logon wallpaper acceptance.
.DESCRIPTION
  Creates standard local users without initializing their profiles. Private intent
  precedes creation; the returned SID is saved before group membership is added.
  Cleanup disables only the recorded user, refuses active or changed profiles,
  and uses DeleteProfileW for the exact owned SID/path before deleting the account.
  No password is persisted or returned. Sign-in and visual evidence are separate.
.NOTES
  Native Windows PowerShell 5.1/7 x64; candidate Windows 11 Enterprise/Education
  Hyper-V guest with existing elevation and correlated test markers. Version: 0.1.1.
  Changelog: 0.1.1: Bind the member SID as a LocalPrincipal-compatible string
  and retain the underlying fixture-creation error for diagnosis.
  No UAC, logon, forced logoff, reboot, checkpoint reset or recursive shell deletion.
  Incomplete creation without a saved SID requires inspection. Failed cleanup may
  leave the owned account disabled; retain its private records and retry cleanup.
.LINK
  ../../docs/image-personalization.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.DefaultWallpaper.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.DefaultWallpaperAcceptance.psm1') -ErrorAction Stop

function Get-RideWallpaperUserContext {
  & (Get-Module RIDE.DefaultWallpaperAcceptance) {Get-RideDefaultWallpaperAcceptanceContext}
}
function Assert-RideWallpaperUserContext {
  param($Context,[string]$RunId,[bool]$DisposableVm,[bool]$Mutation,$Expected)
  if(-not $DisposableVm -or $Context.RunMarker -cne $RunId){throw 'A correlated disposable guest request is required.'}
  & (Get-Module RIDE.DefaultWallpaper) {param($c,$e,$m) Assert-RideDefaultWallpaperContext $c $e $m} $Context $Expected $Mutation
}
function Get-RideWallpaperUserSelection {
  param([string]$RunId,[string]$Purpose,[string]$StateDirectory)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'Invalid fixture request ID.'}
  $purposeNames=@{control='Control';firstlogon='FirstLogon';recovery='Recovery'}
  if(-not $purposeNames.ContainsKey($Purpose.ToLowerInvariant())){throw 'Unknown fixture purpose.'}
  $Purpose=$purposeNames[$Purpose.ToLowerInvariant()]
  $root=& (Get-Module RIDE.DefaultWallpaperAcceptance) {param($p) Assert-RideDefaultWallpaperAcceptanceRoot $p} $StateDirectory
  $name='ridewp_'+$Purpose.Substring(0,1).ToLowerInvariant()+'_'+$RunId.Substring(0,10)
  [pscustomobject]@{RunId=$RunId;Purpose=$Purpose;Name=$name;Description=('RIDE-WP:'+$RunId+':'+$Purpose.Substring(0,1));Root=$root;Prefix=(Join-Path $root ($RunId+'.wallpaper-user.'+$Purpose.ToLowerInvariant()))}
}
function Write-RideWallpaperUserRecord {
  param([string]$Path,$Record)
  & (Get-Module RIDE.DefaultWallpaperAcceptance) {param($p,$r) Save-RideDefaultWallpaperAcceptanceRecord $p $r} $Path $Record
}
function Read-RideWallpaperUserRecord {
  param([string]$Path)
  & (Get-Module RIDE.DefaultWallpaperAcceptance) {param($p) Read-RideDefaultWallpaperAcceptanceRecord $p} $Path
}
function Get-RideWallpaperUserProfileRoot {
  $path=[Environment]::ExpandEnvironmentVariables([string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory))
  if($path -cnotmatch '^[A-Za-z]:\\' -or [IO.Path]::GetFullPath($path) -cne $path -or $path.TrimEnd('\').Length -le 3){throw 'ProfilesDirectory must be a canonical local directory below the drive root.'}
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} (Join-Path $path 'fixture-path-check-only')
  $path.TrimEnd('\')
}
function Get-RideWallpaperUserAccounts {
  $rows=@(Get-LocalUser -ErrorAction Stop)
  if($rows.Count -gt 256){throw 'Local account inventory exceeds its bound.'}
  @($rows|ForEach-Object {[pscustomobject]@{Name=[string]$_.Name;Sid=[string]$_.SID.Value;Description=[string]$_.Description;Enabled=[bool]$_.Enabled;Source=[string]$_.PrincipalSource}})
}
function Get-RideWallpaperUserProfiles {
  $rows=@(Get-CimInstance Win32_UserProfile -ErrorAction Stop)
  if($rows.Count -gt 256){throw 'Profile inventory exceeds its bound.'}
  @($rows|ForEach-Object {[pscustomobject]@{Sid=[string]$_.SID;Path=[string]$_.LocalPath;Loaded=$_.Loaded;Special=$_.Special;Roaming=$_.RoamingConfigured;Status=$_.Status;RefCount=$_.refCount}})
}
function Get-RideWallpaperUserGroups {
  param([string]$Sid)
  $groups=@(Get-LocalGroup -ErrorAction Stop)
  if($groups.Count -gt 128){throw 'Local group inventory exceeds its bound.'}
  @($groups|ForEach-Object {if(@(Get-LocalGroupMember -SID $_.SID -ErrorAction Stop|Where-Object {$_.SID.Value -ceq $Sid}).Count){[string]$_.SID.Value}}|Sort-Object)
}
function Get-RideWallpaperUserSessionCount {
  param([string]$Sid)
  if($Sid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$'){throw 'Invalid local fixture SID.'}
  $account=@(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=TRUE AND SID='$Sid'" -ErrorAction Stop)
  if($account.Count -ne 1){throw 'Local fixture account session identity is unavailable.'}
  @(Get-CimAssociatedInstance -InputObject $account[0] -Association Win32_LoggedOnUser -ResultClassName Win32_LogonSession -ErrorAction Stop).Count
}
function Test-RideWallpaperUserPath {
  param([string]$Path)
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $Path
  if(-not (Test-Path -LiteralPath $Path)){return $false}
  $item=Get-Item -LiteralPath $Path -Force
  if(-not $item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Fixture profile path is not an ordinary local directory.'}
  $true
}
function New-RideWallpaperUserNative {
  param([string]$Name,[string]$Description,[securestring]$Password)
  $user=New-LocalUser -Name $Name -Description $Description -Password $Password -UserMayNotChangePassword -ErrorAction Stop -Confirm:$false
  [string]$user.SID.Value
}
function Add-RideWallpaperUserGroup {
  param([string]$Sid)
  Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $Sid -ErrorAction Stop -Confirm:$false
}
function Disable-RideWallpaperUserNative {
  param([string]$Sid)
  Disable-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($Sid)) -ErrorAction Stop -Confirm:$false
}
function Remove-RideWallpaperUserNative {
  param([string]$Sid)
  Remove-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($Sid)) -ErrorAction Stop -Confirm:$false
}
function Remove-RideWallpaperUserProfileNative {
  param([string]$Sid,[string]$Path)
  if(-not ('Ride.WallpaperUserProfileNative' -as [type])){
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Ride {
  public static class WallpaperUserProfileNative {
    [DllImport("userenv.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeleteProfileW(string sid, string path, IntPtr computer);
    public static void Delete(string sid, string path) {
      if (!DeleteProfileW(sid, path, IntPtr.Zero))
        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
  }
}
'@ -ErrorAction Stop
  }
  [Ride.WallpaperUserProfileNative]::Delete($Sid,$Path)
}
function Read-RideWallpaperUserOwnership {
  param($Selection)
  $intent=Read-RideWallpaperUserRecord ($Selection.Prefix+'.intent.json')
  $created=Read-RideWallpaperUserRecord ($Selection.Prefix+'.created.json')
  foreach($record in @($intent,$created)){
    if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'WallpaperTestUser' -or $record.RunId -cne $Selection.RunId -or $record.Purpose -cne $Selection.Purpose -or $record.Name -cne $Selection.Name -or $record.Description -cne $Selection.Description -or $record.ProfileRoot -cne (Get-RideWallpaperUserProfileRoot) -or $record.ProfilePath -cne (Join-Path $record.ProfileRoot $Selection.Name)){throw 'Fixture ownership record differs.'}
  }
  if($intent.Part -cne 'Intent' -or $created.Part -cne 'Created' -or $created.Sid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or $created.ProfilePath -cne $intent.ProfilePath -or -not (& (Get-Module RIDE.DefaultWallpaperAcceptance) {param($l,$r) Test-RideDefaultWallpaperAcceptanceEqual $l $r} $intent.Context $created.Context)){throw 'Fixture creation receipt differs.'}
  $created
}
function Get-RideWallpaperUserState {
  param($Owned)
  $accounts=@(Get-RideWallpaperUserAccounts)
  $named=@($accounts|Where-Object Name -IEQ $Owned.Name);$matched=@($accounts|Where-Object Sid -CEQ $Owned.Sid)
  if($named.Count -gt 1 -or $matched.Count -gt 1 -or $named.Count -ne $matched.Count -or ($matched.Count -and ($matched[0].Name -cne $Owned.Name -or $named[0].Sid -cne $Owned.Sid -or $matched[0].Description -cne $Owned.Description -or $matched[0].Source -cne 'Local'))){throw 'Owned local account was replaced or changed.'}
  $profiles=@(Get-RideWallpaperUserProfiles)
  $profile=@($profiles|Where-Object Sid -CEQ $Owned.Sid)
  $pathMatches=@($profiles|Where-Object Path -IEQ $Owned.ProfilePath)
  if($profile.Count -gt 1 -or $pathMatches.Count -ne $profile.Count -or ($profile.Count -and ($profile[0].Path -cne $Owned.ProfilePath -or $pathMatches[0].Sid -cne $Owned.Sid -or $profile[0].Special -ne $false -or $profile[0].Roaming -ne $false -or $profile[0].Status -ne 0))){throw 'Owned profile path, identity or type differs.'}
  $exists=Test-RideWallpaperUserPath $Owned.ProfilePath
  if($exists -ne ($profile.Count -eq 1)){throw 'Profile directory and registered profile disagree; no recursive cleanup is permitted.'}
  $groups=if($matched.Count){@(Get-RideWallpaperUserGroups $Owned.Sid)}else{@()}
  if(@($groups|Where-Object {$_ -cne 'S-1-5-32-545'}).Count){throw 'Fixture acquired an unexpected local group; retain it for inspection.'}
  $sessions=if($matched.Count){Get-RideWallpaperUserSessionCount $Owned.Sid}else{0}
  [pscustomobject]@{Account=if($matched.Count){$matched[0]}else{$null};Profile=if($profile.Count){$profile[0]}else{$null};Groups=@($groups);SessionCount=$sessions;ProfileDirectoryExists=$exists}
}
function New-RideWallpaperUserResult {
  param($Selection,[string]$Status,$Owned,$State)
  [pscustomobject]@{SchemaVersion=1;Kind='WallpaperTestUserResult';RunId=$Selection.RunId;Purpose=$Selection.Purpose;Status=$Status;Name=$Selection.Name;Sid=if($Owned){$Owned.Sid}else{$null};ProfilePath=if($Owned){$Owned.ProfilePath}else{$null};State=$State;NativeFirstLogonAcceptancePassed=$false;NativeAcceptancePassed=$false}
}

function New-RideWallpaperTestUser {
  <#
  .SYNOPSIS
    Create one owned standard test account without signing it in.
  .PARAMETER RunId
    Controller request ID matching RIDE_TEST_RUN_ID.
  .PARAMETER Purpose
    Control before applying the theme, FirstLogon after apply, or Recovery after restore.
  .PARAMETER StateDirectory
    Existing administrator-controlled local directory for private fixture records.
  .PARAMETER Password
    Synthetic SecureString, 16-128 characters, required for actual creation only.
    Never persisted or returned. Repeating creation does not change the password.
  .PARAMETER ExpectedComputerName
    Exact selected disposable guest name.
  .PARAMETER ExpectedBuild
    Exact selected Windows 11 build.
  .PARAMETER ExpectedEditionId
    Exact candidate Enterprise/Education edition.
  .PARAMETER DisposableVm
    Required per-invocation disposable-target opt-in; does not bypass native checks.
  .EXAMPLE
    New-RideWallpaperTestUser -RunId $env:RIDE_TEST_RUN_ID -Purpose FirstLogon -StateDirectory C:\RIDE-Test\Users -ExpectedComputerName RIDE-Test -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -DisposableVm -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Created, AlreadyCreated or Preview result without a credential.
  .NOTES
    Keep the credential in the test harness for interactive sign-in. Native password
    policy still applies. Creation and group failures retain intent and any saved SID.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][ValidateSet('Control','FirstLogon','Recovery')][string]$Purpose,
    [Parameter(Mandatory)][string]$StateDirectory,[securestring]$Password,
    [Parameter(Mandatory)][string]$ExpectedComputerName,[Parameter(Mandatory)][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateSet('Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')][string]$ExpectedEditionId,[switch]$DisposableVm)
  $context=Get-RideWallpaperUserContext
  Assert-RideWallpaperUserContext $context $RunId $DisposableVm (-not $WhatIfPreference) $null
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Selected fixture guest differs.'}
  $selection=Get-RideWallpaperUserSelection $RunId $Purpose $StateDirectory
  if(Test-Path -LiteralPath ($selection.Prefix+'.created.json')){
    $owned=Read-RideWallpaperUserOwnership $selection
    Assert-RideWallpaperUserContext $context $RunId $DisposableVm (-not $WhatIfPreference) $owned.Context
    $state=Get-RideWallpaperUserState $owned
    if(-not $state.Account -or -not $state.Account.Enabled -or ($state.Groups -join ';') -cne 'S-1-5-32-545' -or (Test-Path -LiteralPath ($selection.Prefix+'.cleanup-intent.json'))){throw 'Existing fixture is incomplete, changed or being removed; do not recreate it.'}
    return New-RideWallpaperUserResult $selection AlreadyCreated $owned $state
  }
  if(Test-Path -LiteralPath ($selection.Prefix+'.intent.json')){throw 'Incomplete fixture creation; inspect retained intent before recovery.'}
  $root=Get-RideWallpaperUserProfileRoot;$path=Join-Path $root $selection.Name
  if(@(Get-RideWallpaperUserAccounts|Where-Object Name -IEQ $selection.Name).Count -or @(Get-RideWallpaperUserProfiles|Where-Object Path -IEQ $path).Count -or (Test-RideWallpaperUserPath $path)){throw 'The generated account name or profile path already exists; it will not be adopted.'}
  if(-not $WhatIfPreference -and ($null -eq $Password -or $Password.Length -lt 16 -or $Password.Length -gt 128)){throw 'Supply a synthetic SecureString password of 16-128 characters.'}
  if(-not $PSCmdlet.ShouldProcess($context.ComputerName,('Create standard wallpaper test account '+$selection.Name))){return New-RideWallpaperUserResult $selection Preview $null $null}
  $intent=[pscustomobject]@{SchemaVersion=1;Kind='WallpaperTestUser';Part='Intent';RunId=$RunId;Purpose=$selection.Purpose;Name=$selection.Name;Description=$selection.Description;Context=$context;ProfileRoot=$root;ProfilePath=$path;Sid=$null}
  Write-RideWallpaperUserRecord ($selection.Prefix+'.intent.json') $intent
  try{
    Assert-RideWallpaperUserContext (Get-RideWallpaperUserContext) $RunId $DisposableVm $true $context
    if(@(Get-RideWallpaperUserAccounts|Where-Object Name -IEQ $selection.Name).Count -or @(Get-RideWallpaperUserProfiles|Where-Object Path -IEQ $path).Count -or (Test-RideWallpaperUserPath $path)){throw 'Fixture destination changed after intent.'}
    $sid=New-RideWallpaperUserNative $selection.Name $selection.Description $Password
    if($sid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$'){throw 'Native account did not return a local SID.'}
    $created=$intent.PSObject.Copy();$created.Part='Created';$created.Sid=$sid
    Write-RideWallpaperUserRecord ($selection.Prefix+'.created.json') $created
    $state=Get-RideWallpaperUserState $created
    if(-not $state.Account -or -not $state.Account.Enabled -or $state.Profile -or $state.SessionCount){throw 'Fresh fixture account state differs.'}
    if('S-1-5-32-545' -cnotin $state.Groups){Add-RideWallpaperUserGroup $sid}
    $state=Get-RideWallpaperUserState $created
    if(($state.Groups -join ';') -cne 'S-1-5-32-545' -or $state.Profile -or $state.SessionCount){throw 'Standard fixture membership or fresh-profile state differs.'}
    New-RideWallpaperUserResult $selection Created $created $state
  }catch{throw [InvalidOperationException]::new(('Fixture creation incomplete; retain private records for '+$RunId+'/'+$selection.Purpose+'. No automatic account/profile cleanup was attempted. Cause: '+$_.Exception.Message),$_.Exception)}
}

function Get-RideWallpaperTestUser {
  <#
  .SYNOPSIS
    Inspect the owned account/profile without creating evidence or changing Windows.
  .PARAMETER RunId
    Saved controller request ID matching the current guest marker.
  .PARAMETER Purpose
    Saved Control, FirstLogon or Recovery fixture purpose.
  .PARAMETER StateDirectory
    Existing directory containing private intent and created-SID records.
  .PARAMETER DisposableVm
    Required correlated disposable guest attestation.
  .EXAMPLE
    Get-RideWallpaperTestUser -RunId $env:RIDE_TEST_RUN_ID -Purpose FirstLogon -StateDirectory C:\RIDE-Test\Users -DisposableVm
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Observed result; never a first-sign-in or visible-image pass.
  .NOTES
    Private records require their existing access rights. Does not load a profile.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][ValidateSet('Control','FirstLogon','Recovery')][string]$Purpose,
    [Parameter(Mandatory)][string]$StateDirectory,[switch]$DisposableVm)
  $context=Get-RideWallpaperUserContext
  Assert-RideWallpaperUserContext $context $RunId $DisposableVm $false $null
  $selection=Get-RideWallpaperUserSelection $RunId $Purpose $StateDirectory;$owned=Read-RideWallpaperUserOwnership $selection
  Assert-RideWallpaperUserContext $context $RunId $DisposableVm $false $owned.Context
  New-RideWallpaperUserResult $selection Observed $owned (Get-RideWallpaperUserState $owned)
}

function Remove-RideWallpaperTestUser {
  <#
  .SYNOPSIS
    Disable and remove only the recorded disposable user and its unloaded profile.
  .PARAMETER RunId
    Saved controller request ID matching the current guest marker.
  .PARAMETER Purpose
    Saved Control, FirstLogon or Recovery fixture purpose.
  .PARAMETER StateDirectory
    Existing directory containing private intent and created-SID records.
  .PARAMETER DisposableVm
    Required per-invocation disposable-target opt-in for fixture cleanup.
  .EXAMPLE
    Remove-RideWallpaperTestUser -RunId $env:RIDE_TEST_RUN_ID -Purpose FirstLogon -StateDirectory C:\RIDE-Test\Users -DisposableVm -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Removed, AlreadyRemoved or Preview result; no wallpaper acceptance claim.
  .NOTES
    Destructive fixture cleanup: export visual observations first and sign the user
    out normally. Never removes a loaded, active, special, roaming or moved profile.
    A failure retains private intent and may leave the owned account disabled.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][ValidateSet('Control','FirstLogon','Recovery')][string]$Purpose,
    [Parameter(Mandatory)][string]$StateDirectory,[switch]$DisposableVm)
  $context=Get-RideWallpaperUserContext
  Assert-RideWallpaperUserContext $context $RunId $DisposableVm (-not $WhatIfPreference) $null
  $selection=Get-RideWallpaperUserSelection $RunId $Purpose $StateDirectory;$owned=Read-RideWallpaperUserOwnership $selection
  Assert-RideWallpaperUserContext $context $RunId $DisposableVm (-not $WhatIfPreference) $owned.Context
  $state=Get-RideWallpaperUserState $owned
  $intentPath=$selection.Prefix+'.cleanup-intent.json';$removedPath=$selection.Prefix+'.removed.json'
  if(Test-Path -LiteralPath $intentPath){
    $intent=Read-RideWallpaperUserRecord $intentPath
    if($intent.RunId -cne $RunId -or $intent.Purpose -cne $selection.Purpose -or $intent.Sid -cne $owned.Sid -or $intent.ProfilePath -cne $owned.ProfilePath -or $intent.Kind -cne 'WallpaperTestUserCleanup' -or $intent.SchemaVersion -ne 1){throw 'Cleanup intent identity differs.'}
  }else{$intent=$null}
  if(-not $state.Account -and -not $state.Profile){
    if(-not $intent){throw 'Fixture disappeared without a cleanup intent; inspect external changes.'}
    if(Test-Path -LiteralPath $removedPath){
      $done=Read-RideWallpaperUserRecord $removedPath
      if($done.SchemaVersion -ne 1 -or $done.Kind -cne 'WallpaperTestUserResult' -or $done.Sid -cne $owned.Sid -or $done.RunId -cne $RunId -or $done.Purpose -cne $selection.Purpose -or $done.Name -cne $selection.Name -or $done.ProfilePath -cne $owned.ProfilePath -or $done.Status -cne 'Removed' -or $done.NativeAcceptancePassed -ne $false -or $done.NativeFirstLogonAcceptancePassed -ne $false){throw 'Cleanup receipt identity differs.'}
      return New-RideWallpaperUserResult $selection AlreadyRemoved $owned $state
    }
  }elseif(-not $state.Account){throw 'Account is absent while its profile remains; retain it for inspection.'}
  if($state.SessionCount -ne 0 -or ($state.Profile -and ($state.Profile.Loaded -ne $false -or $state.Profile.RefCount -gt 0))){throw 'Fixture has an active session or loaded profile; sign out normally before cleanup.'}
  if(-not $PSCmdlet.ShouldProcess($context.ComputerName,('Remove owned wallpaper test account/profile '+$selection.Name))){return New-RideWallpaperUserResult $selection Preview $owned $state}
  if(-not $intent){Write-RideWallpaperUserRecord $intentPath ([pscustomobject]@{SchemaVersion=1;Kind='WallpaperTestUserCleanup';RunId=$RunId;Purpose=$selection.Purpose;Sid=$owned.Sid;ProfilePath=$owned.ProfilePath})}
  $stage='DisableAccount'
  try{
    Assert-RideWallpaperUserContext (Get-RideWallpaperUserContext) $RunId $DisposableVm $true $owned.Context
    $state=Get-RideWallpaperUserState $owned
    if($state.SessionCount -ne 0 -or ($state.Profile -and ($state.Profile.Loaded -ne $false -or $state.Profile.RefCount -gt 0))){throw 'Fixture became active before cleanup.'}
    if($state.Account -and $state.Account.Enabled){Disable-RideWallpaperUserNative $owned.Sid}
    $stage='RemoveProfile';$state=Get-RideWallpaperUserState $owned
    if($state.SessionCount -ne 0 -or ($state.Account -and $state.Account.Enabled) -or ($state.Profile -and (-not $state.Account -or $state.Profile.Loaded -ne $false -or $state.Profile.RefCount -gt 0))){throw 'Disabled account or unloaded profile did not verify.'}
    if($state.Profile){Remove-RideWallpaperUserProfileNative $owned.Sid $owned.ProfilePath}
    $stage='RemoveAccount';$state=Get-RideWallpaperUserState $owned
    if($state.Profile -or $state.ProfileDirectoryExists -or $state.SessionCount -ne 0 -or ($state.Account -and $state.Account.Enabled)){throw 'Profile removal did not verify.'}
    if($state.Account){Remove-RideWallpaperUserNative $owned.Sid}
    $stage='Verify';$state=Get-RideWallpaperUserState $owned
    if($state.Account -or $state.Profile -or $state.ProfileDirectoryExists){throw 'Final fixture cleanup did not verify.'}
    $result=New-RideWallpaperUserResult $selection Removed $owned $state
    Write-RideWallpaperUserRecord $removedPath $result
    $result
  }catch{
    Write-RideWallpaperUserRecord ($selection.Prefix+'.failure.'+[guid]::NewGuid().ToString('N')+'.json') ([pscustomobject]@{SchemaVersion=1;Kind='WallpaperTestUserCleanupFailure';RunId=$RunId;Purpose=$selection.Purpose;Sid=$owned.Sid;Stage=$stage;RecoveryRequired=$true})
    throw ('Fixture cleanup incomplete at '+$stage+'; retain private records and the guest. The owned account may be disabled; no automatic logoff/reset was attempted.')
  }
}
$script:WallpaperUserCompleter={
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{
    $ids=@()
    if($commandName -ieq 'New-RideWallpaperTestUser' -and $env:RIDE_TEST_RUN_ID -cmatch '^[a-f0-9]{32}$'){$ids+=@($env:RIDE_TEST_RUN_ID)}
    if($fakeBoundParameters.ContainsKey('StateDirectory')){
      $ids+=@(Get-ChildItem -LiteralPath $fakeBoundParameters.StateDirectory -Filter '*.wallpaper-user.*.created.json' -File -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {
        if($_.Name -cmatch '^([a-f0-9]{32})\.wallpaper-user\.(control|firstlogon|recovery)\.created\.json$'){$Matches[1]}
      })
    }
    $ids|Where-Object {$_.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)}|Sort-Object -Unique|ForEach-Object {[Management.Automation.CompletionResult]::new($_,$_,'ParameterValue','Correlated wallpaper test-user request')}
  }catch{}
}
Register-ArgumentCompleter -CommandName New-RideWallpaperTestUser,Get-RideWallpaperTestUser,Remove-RideWallpaperTestUser -ParameterName RunId -ScriptBlock $script:WallpaperUserCompleter
Export-ModuleMember -Function New-RideWallpaperTestUser,Get-RideWallpaperTestUser,Remove-RideWallpaperTestUser
