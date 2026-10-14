<#
.SYNOPSIS
  Hand explicit user-only RIDE actions to the current desktop user's process.
.DESCRIPTION
  Uses the existing desktop shell, never an administrator token with privileges
  removed. The child verifies SID, session, shell identity and source before any
  engine action. Launch receipts are not completion or recovery evidence.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows, desktop required.
  Prerequisites: Unelevated Explorer in the caller's current nonzero session.
  File/environment inputs: Current repository modules/catalog and explicit libraries.
  Recovery: Child engine state belongs to the desktop user; mixed scope is refused.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add explicit same-session user-only launch and worker preflight.
  Design reference: https://devblogs.microsoft.com/oldnewthing/20131118-00/?p=2643
#>
$ErrorActionPreference='Stop'
$script:HandoffRoot=Split-Path -Parent $PSScriptRoot

function Get-RideHandoffHash($Value) {
  function ConvertTo-HandoffData($v) {
    if($null -eq $v){return $null}
    if($v -is [Collections.IDictionary]){
      $d=[ordered]@{};foreach($k in @($v.Keys|Sort-Object)){$d[$k]=ConvertTo-HandoffData $v[$k]};return $d
    }
    if($v -is [Collections.IEnumerable] -and $v -isnot [string]){return ,@(foreach($x in $v){ConvertTo-HandoffData $x})}
    $v
  }
  $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-HandoffData $Value|ConvertTo-Json -Depth 40 -Compress))
  $sha=[Security.Cryptography.SHA256]::Create()
  try{([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}finally{$sha.Dispose()}
}

function Get-RideHandoffSourceHash {
  $files=@(Get-Item -LiteralPath (Join-Path $script:HandoffRoot 'ride.ps1'))
  $directories=[Collections.Generic.Queue[string]]::new()
  foreach($dir in @('modules','catalog')){
    $directories.Enqueue((Join-Path $script:HandoffRoot $dir))
  }
  $entryCount=0
  while($directories.Count){
    $root=$directories.Dequeue()
    if((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Handoff source directory cannot be a reparse point.'}
    foreach($entry in Get-ChildItem -LiteralPath $root -Force){
      $entryCount++
      if($entryCount -gt 2000){throw 'Handoff source exceeds its entry bound.'}
      if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Handoff source entry cannot be a reparse point.'}
      if($entry.PSIsContainer){$directories.Enqueue($entry.FullName)}else{$files+=@($entry)}
    }
  }
  if($files.Count -gt 2000){throw 'Handoff source exceeds its file bound.'}
  $rows=[ordered]@{}
  foreach($file in $files|Sort-Object FullName){
    if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Handoff source file cannot be a reparse point.'}
    $rows[$file.FullName.Substring($script:HandoffRoot.Length).Replace('\','/')]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
  }
  Get-RideHandoffHash $rows
}

function Initialize-RideHandoffNative {
  if('Ride.DesktopHandoffV1' -as [type]){return}
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace Ride {
 public static class DesktopHandoffV1 {
  [DllImport("user32.dll")] public static extern IntPtr GetShellWindow();
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd,out uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr buffer,int length,out int needed);
  public static uint WindowPid(long hwnd) { uint pid; GetWindowThreadProcessId(new IntPtr(hwnd),out pid); return pid; }
  public static string[] ReadShell() {
   IntPtr hwnd=GetShellWindow(); if(hwnd==IntPtr.Zero) throw new InvalidOperationException("No desktop shell in the current session.");
   uint pid; GetWindowThreadProcessId(hwnd,out pid);
   IntPtr process=OpenProcess(0x1000,false,pid); if(process==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
   IntPtr token=IntPtr.Zero,buffer=IntPtr.Zero;
   try {
    if(!OpenProcessToken(process,8,out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
    int needed; GetTokenInformation(token,1,IntPtr.Zero,0,out needed);
    if(needed<=0 || needed>65536) throw new InvalidOperationException("Invalid desktop token size.");
    buffer=Marshal.AllocHGlobal(needed);
    if(!GetTokenInformation(token,1,buffer,needed,out needed)) throw new Win32Exception(Marshal.GetLastWin32Error());
    string sid=new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
    Marshal.FreeHGlobal(buffer);buffer=IntPtr.Zero;buffer=Marshal.AllocHGlobal(4);
    if(!GetTokenInformation(token,20,buffer,4,out needed)) throw new Win32Exception(Marshal.GetLastWin32Error());
    bool elevated=Marshal.ReadInt32(buffer)!=0;
    int session; using(Process p=Process.GetProcessById((int)pid)) { session=p.SessionId; }
    return new string[]{sid,session.ToString(),pid.ToString(),elevated.ToString()};
   } finally { if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer); if(token!=IntPtr.Zero) CloseHandle(token);CloseHandle(process); }
  }
 }
}
'@ -ErrorAction Stop
}

function Get-RideDesktopHandoffContext {
  Initialize-RideHandoffNative
  $shell=[Ride.DesktopHandoffV1]::ReadShell()
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try {
    [pscustomobject]@{TargetSid=$shell[0];SessionId=[int]$shell[1];ShellProcessId=[int]$shell[2];ShellElevated=[bool]::Parse($shell[3]);CurrentSessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;CurrentSid=$identity.User.Value;CurrentElevated=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
  }finally{$identity.Dispose()}
}

function Assert-RideDesktopHandoffContext($Context) {
  if($Context.TargetSid -notmatch '^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$' -or $Context.SessionId -le 0 -or $Context.SessionId -ne $Context.CurrentSessionId -or $Context.ShellProcessId -le 0 -or $Context.ShellElevated){throw 'Handoff requires the unelevated signed-in desktop user in the current session.'}
}

function Assert-RideHandoffUserPlan([object[]]$Plan) {
  if(-not $Plan.Count -or $Plan.Count -gt 100){throw 'Desktop handoff requires 1-100 user setting operations.'}
  foreach($item in $Plan){
    if($item.Operation.Scope -ne 'User' -or $item.Operation.RequiresAdmin -or $item.Operation.Kind -in @('Package','Artifact') -or 'Set' -notin $item.Operation.Actions -or 'Restore' -notin $item.Operation.Actions){throw 'Desktop handoff accepts user-only settings; machine, mixed and package actions require separate execution.'}
  }
}

function Get-RideHandoffUserStateRoot {
  & (Get-Module RIDE.Engine) {Get-RideStateRoot -Scope User}
}

function Get-RideHandoffPlan([string]$Command,[string]$Id,[string]$State,[string]$Profile,[string[]]$Library) {
  Import-Module (Join-Path $PSScriptRoot 'RIDE.Engine.psm1') -Force -Scope Local
  Set-RideLibraryContext -Library $Library
  switch($Command){
    set { @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $State) }
    unset { @(Get-RideSingleOperationPlan -Id $Id -Action Unset) }
    default { @(Get-RidePlan -Profile (Get-RideProfile -Path $Profile)) }
  }
}

function Start-RideHandoffShellProcess($Context,[string]$Arguments) {
  $collection=$null;$desktop=$null;$document=$null;$application=$null
  try {
    $collection=[Activator]::CreateInstance([type]::GetTypeFromCLSID([guid]'9BA05972-F6A8-11CF-A442-00A0C90A8F39'))
    $hwnd=0;$desktop=$collection.FindWindowSW(0,0,8,[ref]$hwnd,1)
    if(-not $desktop -or [Ride.DesktopHandoffV1]::WindowPid([long]$hwnd) -ne $Context.ShellProcessId){throw 'Desktop automation identity changed; no handoff launched.'}
    $current=Get-RideDesktopHandoffContext;Assert-RideDesktopHandoffContext $current
    if($current.TargetSid -cne $Context.TargetSid -or $current.SessionId -ne $Context.SessionId -or $current.ShellProcessId -ne $Context.ShellProcessId){throw 'Desktop user/session changed; no handoff launched.'}
    $document=$desktop.Document;$application=$document.Application
    $exe=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
    $application.ShellExecute($exe,$Arguments,$script:HandoffRoot,'open',1)
  }finally{
    foreach($value in @($application,$document,$desktop,$collection)){if($null -ne $value -and [Runtime.InteropServices.Marshal]::IsComObject($value)){[void][Runtime.InteropServices.Marshal]::ReleaseComObject($value)}}
  }
}

function Start-RideDesktopUserHandoff {
  <#
  .SYNOPSIS
    Launch a user-only action through the verified current desktop shell.
  .DESCRIPTION
    Prepares bounded setting data and asks the existing desktop shell to launch
    the worker. Identity, source and contract checks run again in the child.
  .PARAMETER Command
    Set, unset, apply, plan or restore; mixed plans and packages are refused.
  .PARAMETER Id
    Catalog setting ID for set/unset.
  .PARAMETER State
    Catalog state for set.
  .PARAMETER Profile
    User-only profile for apply/plan.
  .PARAMETER RunId
    Desktop user's saved run for restore.
  .PARAMETER Library
    Explicit local libraries, resolved to absolute paths before launch.
  .EXAMPLE
    Start-RideDesktopUserHandoff set -Id windows.show-known-extensions -State Enabled -WhatIf
  .INPUTS
    None. Parameters are supplied explicitly.
  .OUTPUTS
    PSCustomObject. Preview/launch receipt only; completion appears in the user window.
  .NOTES
    Version 0.1.0. WhatIf starts no process and writes no handoff files. No credentials,
    UAC changes, execution-policy bypass, scheduled tasks or machine/user splitting.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
  param([Parameter(Mandatory)][ValidateSet('set','unset','apply','plan','restore')][string]$Command,[string]$Id,[string]$State,[string]$Profile,[string]$RunId,[string[]]$Library=@())
  $context=Get-RideDesktopHandoffContext;Assert-RideDesktopHandoffContext $context
  $paths=@($Library|ForEach-Object {(Resolve-Path -LiteralPath $_ -ErrorAction Stop).ProviderPath})
  if($paths.Count -gt 8){throw 'Desktop handoff supports at most eight explicit libraries.'}
  $items=@()
  if($Command -eq 'restore'){
    if($RunId -notmatch '^[0-9a-fA-F]{32}$'){throw 'Desktop restore requires a 32-character saved run ID.'}
    $RunId=$RunId.ToLowerInvariant()
  }else{
    $plan=@(Get-RideHandoffPlan $Command $Id $State $Profile $paths)
    Assert-RideHandoffUserPlan $plan
    $items=@($plan|ForEach-Object {[ordered]@{Id=$_.Operation.Id;State=$_.State;ContractHash=Get-RideHandoffHash $_.Operation}})
  }
  $request=[ordered]@{SchemaVersion=1;RequestId=[guid]::NewGuid().ToString('N');Root=$script:HandoffRoot;SourceHash=Get-RideHandoffSourceHash;TargetSid=$context.TargetSid;SessionId=$context.SessionId;ShellProcessId=$context.ShellProcessId;Command=$Command;RunId=$RunId;Items=$items;Library=$paths;Confirm=[bool]$PSBoundParameters['Confirm']}
  $json=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Depth 10 -Compress)))
  # Only encoded JSON data is substituted; paths/IDs/states are never PowerShell code.
  $bootstrap=@'
$ErrorActionPreference='Stop'
try {
 $r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUEST__'))|ConvertFrom-Json
 $i=[Security.Principal.WindowsIdentity]::GetCurrent()
 try {
  if($i.User.Value -cne $r.TargetSid -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne $r.SessionId -or ([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Desktop worker identity/session/elevation mismatch; nothing applied.'}
 }finally{$i.Dispose()}
 Import-Module (Join-Path $r.Root 'modules/RIDE.UserHandoff.psm1') -Force -ErrorAction Stop
 Invoke-RideDesktopUserRequest -Request $r
}catch{Write-Error -ErrorRecord $_ -ErrorAction Continue}
'@
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap.Replace('__REQUEST__',$json)))
  $arguments='-NoProfile -NoExit -EncodedCommand '+$encoded
  if($arguments.Length -gt 30000){throw 'Desktop handoff exceeds the bounded command-line size; use a smaller user-only selection.'}
  $launched=$false
  if($PSCmdlet.ShouldProcess("$($context.TargetSid), session $($context.SessionId)","Launch desktop-user $Command; completion and saved run IDs appear in its window")){
    Start-RideHandoffShellProcess $context $arguments;$launched=$true
  }
  [pscustomobject]@{Status=$(if($launched){'Launched'}else{'NotLaunched'});RequestId=$request.RequestId;TargetSid=$context.TargetSid;SessionId=$context.SessionId;Command=$Command;OperationIds=@($items.Id);CompletionVerified=$false;Recovery='Desktop user state; inspect the child window for actual outcome and run IDs'}
}

function Invoke-RideDesktopUserRequest {
  <#
  .SYNOPSIS
    Revalidate and execute an encoded user-only request inside the desktop process.
  .DESCRIPTION
    Refuses mismatched users, sessions, source and saved recovery before changes.
    Engine results belong to this user's window and ordinary state namespace.
  .PARAMETER Request
    Correlated schema-1 data from Start-RideDesktopUserHandoff, never executable code.
  .EXAMPLE
    Get-Help Invoke-RideDesktopUserRequest -Full
    Inspect worker boundaries without invoking a desktop action.
  .INPUTS
    None. The encoded request is supplied explicitly by the desktop bootstrap.
  .OUTPUTS
    Engine progress, plan output or an error. State is saved under the actual user.
  .NOTES
    Version 0.1.0. All identity/source/plan checks precede changes. The caller must
    already be the unelevated target desktop user. No privileged broker is invoked.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Request)
  $keys=@('SchemaVersion','RequestId','Root','SourceHash','TargetSid','SessionId','ShellProcessId','Command','RunId','Items','Library','Confirm')
  if(@($Request.PSObject.Properties).Count -ne $keys.Count -or @($Request.PSObject.Properties.Name|Where-Object {$_ -notin $keys}).Count -or $Request.SchemaVersion -ne 1 -or $Request.RequestId -notmatch '^[0-9a-f]{32}$' -or $Request.SourceHash -notmatch '^[0-9A-F]{64}$' -or $Request.Command -notin @('set','unset','apply','plan','restore') -or -not [string]::Equals([IO.Path]::GetFullPath($Request.Root),[IO.Path]::GetFullPath($script:HandoffRoot),[StringComparison]::OrdinalIgnoreCase) -or @($Request.Library).Count -gt 8 -or $Request.Confirm -isnot [bool]){throw 'Invalid desktop handoff request.'}
  $context=Get-RideDesktopHandoffContext;Assert-RideDesktopHandoffContext $context
  if($context.CurrentSid -cne $Request.TargetSid -or $context.TargetSid -cne $Request.TargetSid -or $context.CurrentElevated -or $context.SessionId -ne $Request.SessionId -or $context.ShellProcessId -ne $Request.ShellProcessId){throw 'Desktop worker identity/session/elevation mismatch; nothing applied.'}
  if((Get-RideHandoffSourceHash) -cne $Request.SourceHash){throw 'RIDE source changed after desktop handoff preparation; nothing applied.'}
  Import-Module (Join-Path $PSScriptRoot 'RIDE.Engine.psm1') -Force -Scope Local
  Set-RideLibraryContext -Library @($Request.Library)
  if($Request.Command -eq 'restore'){
    if(@($Request.Items).Count -or $Request.RunId -notmatch '^[0-9a-fA-F]{32}$'){throw 'Invalid desktop restore request.'}
    $Request.RunId=$Request.RunId.ToLowerInvariant()
    $root=Get-RideHandoffUserStateRoot
    $directory=Join-Path $root $Request.RunId
    $manifestPath=Join-Path $directory '_manifest.json'
    if(((Get-Item -LiteralPath $directory -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-Item -LiteralPath $manifestPath -ErrorAction Stop).Length -gt 1048576 -or ((Get-Item -LiteralPath $manifestPath -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Invalid desktop recovery directory/manifest.'}
    $manifest=Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop|ConvertFrom-Json
    if($manifest.SchemaVersion -notin @(1,2) -or $manifest.RunId -cne $Request.RunId -or @($manifest.Scopes).Count -ne 1 -or $manifest.Scopes[0] -ne 'User' -or -not @($manifest.OperationIds).Count -or @($manifest.OperationIds).Count -gt 100){throw 'Desktop recovery requires a user-only saved manifest.'}
    $records=@(Get-ChildItem -LiteralPath $directory -Filter '*.json' -File|Where-Object Name -ne '_manifest.json')
    if(-not $records.Count -or $records.Count -gt 100){throw 'Desktop recovery requires bounded saved user records.'}
    $catalog=Get-RideCatalog
    foreach($file in $records){
      if($file.Length -gt 1048576 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Invalid desktop recovery record.'}
      $record=Get-Content -LiteralPath $file.FullName -Raw|ConvertFrom-Json
      $operation=$catalog.Operations|Where-Object Id -eq $record.OperationId|Select-Object -First 1
      if($record.SchemaVersion -notin @(1,2) -or $record.RunId -cne $Request.RunId -or $record.Scope -ne 'User' -or -not $operation -or $record.OperationId -notin $manifest.OperationIds -or $file.Name -ne (($record.OperationId -replace '[^a-zA-Z0-9._-]','_')+'.json') -or $record.Kind -ne $operation.Kind){throw 'Desktop recovery record identity changed.'}
      Assert-RideHandoffUserPlan @([pscustomobject]@{Operation=$operation})
    }
    if((Get-RideHandoffSourceHash) -cne $Request.SourceHash){throw 'RIDE source changed during desktop recovery preflight; nothing applied.'}
    Restore-RideRun -RunId $Request.RunId -Confirm:$Request.Confirm
  }else{
    if(-not @($Request.Items).Count -or @($Request.Items).Count -gt 100){throw 'Invalid desktop plan size.'}
    $plan=@(foreach($item in $Request.Items){
      if(@($item.PSObject.Properties).Count -ne 3 -or @($item.PSObject.Properties.Name|Where-Object {$_ -notin @('Id','State','ContractHash')}).Count -or $item.Id -isnot [string] -or $item.State -isnot [string] -or $item.ContractHash -notmatch '^[0-9A-F]{64}$'){throw 'Invalid desktop plan item.'}
      $entry=@(Get-RideSingleOperationPlan -Id $item.Id -Action Set -State $item.State)
      if($entry.Count -ne 1 -or (Get-RideHandoffHash $entry[0].Operation) -cne $item.ContractHash){throw 'Desktop operation contract changed; nothing applied.'}
      $entry[0]
    })
    Assert-RideHandoffUserPlan $plan
    if((Get-RideHandoffSourceHash) -cne $Request.SourceHash){throw 'RIDE source changed during desktop preflight; nothing applied.'}
    if($Request.Command -eq 'plan'){Show-RidePlan -Plan $plan}
    else{Invoke-RidePlan -Plan $plan -Confirm:$Request.Confirm}
  }
}

Export-ModuleMember -Function Start-RideDesktopUserHandoff,Invoke-RideDesktopUserRequest
