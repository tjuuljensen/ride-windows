<#
.SYNOPSIS
  Verify redirected Documents and alternate-account profile isolation in a disposable VM.
.DESCRIPTION
  Coordinator temporarily redirects its Documents known folder and runs profile
  round trips through real runtime discovery. A newly generated guest administrator
  runs a password-logon task to verify its own paths and reject another SID's snapshot.
  Restores known-folder values, profile bytes and its task/account in finally blocks.
.PARAMETER Role
  Coordinator or AlternateAccount; default Coordinator.
.PARAMETER ExpectedComputerName
  Exact attested disposable guest name.
.PARAMETER EvidencePath
  Evidence directory beneath C:\RIDE\ProfileAcceptance.
.PARAMETER DisposableVm
  Required guest attestation, together with RIDE_INTEGRATION_VM=1.
.PARAMETER Version
  Print the version without accessing Windows state.
.EXAMPLE
  .\Invoke-RideProfileIdentityAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  JSON identity and redirected-path evidence; failures throw.
.NOTES
  Compatibility: Windows PowerShell 5.1 on disposable Windows desktop guests.
  Prerequisites: Elevated coordinator, installed PowerShell 7, local task/account APIs.
  Recovery: Exact known-folder values/profile content, owned task/account removal,
  followed by the host runner's pinned clean checkpoint restore.
  Author: RIDE-Windows maintainers. Version: 0.1.1.
  Changelog: 0.1.1: Keep color acceptance scoped away from other profile renderers.
    0.1.0: Add real known-folder and alternate-account isolation checks.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([ValidateSet('Coordinator','AlternateAccount')][string]$Role = 'Coordinator',
  [string]$ExpectedComputerName, [string]$EvidencePath, [switch]$DisposableVm, [switch]$Version)
$script:ScriptVersion = '0.1.1'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $DisposableVm -or $env:RIDE_INTEGRATION_VM -ne '1' -or $env:COMPUTERNAME -ine $ExpectedComputerName -or
    (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine') { throw 'Identity acceptance requires the attested disposable guest.' }
$evidence = [IO.Path]::GetFullPath($EvidencePath)
if (-not $evidence.StartsWith('C:\RIDE\ProfileAcceptance\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected identity evidence directory.' }
if (-not $PSCmdlet.ShouldProcess($ExpectedComputerName,"Run $Role profile identity acceptance")) { return }
$env:PATH = (Join-Path $env:ProgramFiles 'PowerShell/7') + ';' + $env:PATH
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE-ProfileSettings.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.CatalogData.psm1') -Force
$operations = @((Import-RideCatalogData (Join-Path $PSScriptRoot '../../catalog/operations.psd1')).Operations | Where-Object ProfileSetting -eq TerminalColors)
function Assert-IdentityAcceptance([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }

if ($Role -eq 'AlternateAccount') {
  $rows = @(); $failure = $null
  try {
    $foreign = Get-Content -LiteralPath (Join-Path $evidence 'foreign-snapshot.json') -Raw | ConvertFrom-Json
    foreach ($operation in $operations) {
      $before = Get-RideProfileSettingState $operation
      Assert-IdentityAcceptance ($before.Available -and $before.OwnerSid -cne $foreign.OwnerSid) 'Alternate account identity was not isolated.'
      Assert-IdentityAcceptance ($before.Path.StartsWith($env:USERPROFILE + '\',[StringComparison]::OrdinalIgnoreCase)) 'Alternate profile escaped its own user directory.'
      $snapshot = Get-RideProfileSettingSnapshot $operation $before Recommended
      try {
        Set-RideProfileSettingState $operation Recommended -ExpectedState $before -Confirm:$false
        $rejected = $false
        try { Restore-RideProfileSettingState $operation $foreign -ValidateOnly } catch { $rejected = $_.Exception.Message -like '*identity, version or path mismatch*' }
        Assert-IdentityAcceptance $rejected 'A foreign-account snapshot was accepted.'
      } finally { Restore-RideProfileSettingState $operation $snapshot -Confirm:$false }
      $after = Get-RideProfileSettingState $operation
      Assert-IdentityAcceptance ($after.FileExists -eq $before.FileExists -and $after.FileBase64 -ceq $before.FileBase64) 'Alternate account profile recovery failed.'
      $rows += @{ Runtime = $operation.ProfileRuntime; Sid = $before.OwnerSid; Path = $before.Path; ForeignSnapshotRejected = $true; Recovery = 'Passed' }
    }
  } catch { $failure = $_.Exception.Message }
  finally { @{ Status = if ($failure) { 'Failed' } else { 'Passed' }; Error = $failure; Cases = $rows } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'alternate-account.json') -Encoding UTF8 }
  if ($failure) { throw $failure }; return
}

$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Identity coordinator requires guest elevation.' }
$keys = @(); $redirected = @()
$redirect = Join-Path $env:USERPROFILE ('RIDE redirected documents ' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($redirect)
try {
  foreach ($subkey in @('Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders','Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders')) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($subkey,$true)
    if (-not $key) { throw 'Guest known-folder registry key is unavailable.' }
    $exists = 'Personal' -in $key.GetValueNames()
    $keys += @{ Key = $key; Exists = $exists; Value = $key.GetValue('Personal',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); Kind = if ($exists) { $key.GetValueKind('Personal') } else { [Microsoft.Win32.RegistryValueKind]::String } }
    $key.SetValue('Personal',$redirect,[Microsoft.Win32.RegistryValueKind]::ExpandString)
  }
  foreach ($operation in $operations) {
    $before = Get-RideProfileSettingState $operation
    Assert-IdentityAcceptance ($before.Path.StartsWith($redirect + '\',[StringComparison]::OrdinalIgnoreCase)) 'Runtime discovery did not follow redirected Documents.'
    $snapshot = Get-RideProfileSettingSnapshot $operation $before Recommended
    try { Set-RideProfileSettingState $operation Recommended -ExpectedState $before -Confirm:$false }
    finally { Restore-RideProfileSettingState $operation $snapshot -Confirm:$false }
    $after = Get-RideProfileSettingState $operation
    Assert-IdentityAcceptance ($after.FileExists -eq $before.FileExists -and $after.FileBase64 -ceq $before.FileBase64) 'Redirected profile recovery failed.'
    $redirected += @{ Runtime = $operation.ProfileRuntime; Sid = $before.OwnerSid; Path = $before.Path; Recovery = 'Passed' }
  }
} finally {
  foreach ($saved in $keys) {
    try { if ($saved.Exists) { $saved.Key.SetValue('Personal',$saved.Value,$saved.Kind) } else { $saved.Key.DeleteValue('Personal',$false) } } finally { $saved.Key.Dispose() }
  }
}
$redirected | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $evidence 'redirected-documents.json') -Encoding UTF8
$alternate = Join-Path $evidence 'alternate'
$null = [IO.Directory]::CreateDirectory($alternate)
$before = Get-RideProfileSettingState $operations[0]
Get-RideProfileSettingSnapshot $operations[0] $before Recommended | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $alternate 'foreign-snapshot.json') -Encoding UTF8
$name = 'RIDEProf' + [guid]::NewGuid().ToString('N').Substring(0,10)
$taskName = 'RIDE-ProfileIdentity-' + [guid]::NewGuid().ToString('N')
$password = ConvertTo-SecureString ([guid]::NewGuid().ToString('N') + 'Aa1!') -AsPlainText -Force
$account = $null; $task = $null
try {
  $account = New-LocalUser -Name $name -Password $password -Description 'Disposable RIDE profile identity acceptance'
  Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $account
  $acl = Get-Acl -LiteralPath $alternate
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account.SID,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
  Set-Acl -LiteralPath $alternate -AclObject $acl
  $command = '$env:RIDE_INTEGRATION_VM=''1''; & ' + "'$($PSCommandPath.Replace("'","''"))' -Role AlternateAccount -ExpectedComputerName '$ExpectedComputerName' -EvidencePath '$alternate' -DisposableVm -Confirm:`$false *> '$alternate/account.log'"
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
  $action = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe') -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
  $task = Register-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -Action $action -User ($env:COMPUTERNAME + '\' + $name) -Password ([pscredential]::new($name,$password).GetNetworkCredential().Password) -RunLevel Highest
  Start-ScheduledTask -InputObject $task
  $deadline = [datetime]::UtcNow.AddMinutes(3)
  $resultPath = Join-Path $alternate 'alternate-account.json'
  while (-not [IO.File]::Exists($resultPath) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 1 }
  if (-not [IO.File]::Exists($resultPath)) { throw 'Alternate-account task did not produce evidence; see account.log.' }
  $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
  Assert-IdentityAcceptance ($result.Status -eq 'Passed') ('Alternate-account acceptance failed: ' + $result.Error)
  foreach ($row in $result.Cases) { Assert-IdentityAcceptance ($row.Sid -ceq $account.SID.Value) 'Alternate task SID mismatch.' }
} finally {
  if ($task) { Stop-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue; Unregister-ScheduledTask -InputObject $task -Confirm:$false }
  if ($account) { Remove-LocalUser -SID $account.SID }
}
