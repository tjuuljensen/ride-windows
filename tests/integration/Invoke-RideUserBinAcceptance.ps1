<#
.SYNOPSIS
  Verify both user-bin startup candidates in a disposable Windows 11 guest.
.DESCRIPTION
  Uses the current guest account, real runtime profile discovery and saved runs.
  Starts ConsoleHost processes with and without profiles, checks missing and
  existing bin directories and duplicate entries, then restores original bytes.
  Requires an initially absent bin directory; never adopts existing contents.
  The outer serialized runner retains source/evidence and restores its checkpoint.
.PARAMETER Stage
  Prepare checks installed runtimes without acquiring or installing anything; Run
  executes the lifecycle and startup cases.
.PARAMETER ExpectedComputerName
  Exact disposable guest identity supplied by the host runner.
.PARAMETER EvidencePath
  Run evidence beneath C:\RIDE\ProfileAcceptance.
.PARAMETER PrerequisiteEvidencePath
  Must be empty. This scenario does not acquire prerequisites.
.PARAMETER DisposableVm
  Required disposable-guest attestation.
.PARAMETER Version
  Return the version before accessing the guest.
.EXAMPLE
  .\Invoke-RideUserBinAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  Preparation status or startup/lifecycle evidence objects.
.NOTES
  Compatibility: Windows PowerShell 5.1 coordinator; Windows 11 disposable guest.
  Prerequisites: Both PowerShell runtimes installed; existing pinned VM workflow.
  Recovery: Saved runs, owned empty fixture directory cleanup, outer checkpoint.
  Version: 0.1.0. Changelog: 0.1.0: Add current-source startup acceptance case.
#>


[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [ValidateSet('Prepare','Run')][string]$Stage = 'Run',
  [string]$ExpectedComputerName, [string]$EvidencePath,
  [string]$PrerequisiteEvidencePath, [switch]$DisposableVm, [switch]$Version
)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $DisposableVm -or $env:RIDE_INTEGRATION_VM -ne '1' -or -not $ExpectedComputerName -or
    $env:COMPUTERNAME -ine $ExpectedComputerName -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine') {
  throw 'Use the attested disposable guest runner; no workstation integration is permitted.'
}
if ($PrerequisiteEvidencePath) { throw 'Prerequisite installation is outside this scenario.' }
$evidence = [IO.Path]::GetFullPath($EvidencePath)
if (-not $evidence.StartsWith('C:\RIDE\ProfileAcceptance\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence must belong to this guest run.' }
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE-ProfileSettings.psm1') -Global
if ((Get-RidePlatform) -ne 'Windows 11') { throw 'This startup case is limited to Windows 11.' }
$runtimes = @{
  WindowsPowerShell51 = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
  PowerShell7 = Join-Path $env:ProgramFiles 'PowerShell/7/pwsh.exe'
}
foreach ($path in $runtimes.Values) { if (-not [IO.File]::Exists($path)) { throw "Installed runtime required: $path" } }
if ($Stage -eq 'Prepare') { [pscustomobject]@{ RebootRequired = $false; Runtimes = $runtimes }; return }
if (-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Verify user-bin profile lifecycle and startup')) { return }
$null = New-Item -ItemType Directory -Path $evidence -Force
$bin = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'bin'
if (Test-Path -LiteralPath $bin) { throw 'The missing-bin case requires an absent bin directory; existing contents are preserved.' }
$catalog = Get-RideCatalog
$operations = @($catalog.Operations | Where-Object ProfileSetting -eq UserBinPath)
if ($operations.Count -ne 2) { throw 'Expected both user-bin runtime candidates.' }
foreach ($op in $operations) {
  if ('Windows 11' -notin $op.CandidateTargets) { throw 'Windows 11 must be a declared candidate.' }
  $op.SupportedTargets = @('Windows 11'); $op.PendingAcceptance = $false
}
& (Get-Module RIDE.Engine) { param($Catalog) $script:RideLibraryContext = @{Catalog=$Catalog;Libraries=@();ProfileFiles=@()} } $catalog
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$runs = [Collections.Generic.List[string]]::new()
$rows = [Collections.Generic.List[object]]::new()
$originals = @{}; $ownsBin = $false; $failure = $null
$sentinel = Join-Path $bin ('ride-fixture-' + [guid]::NewGuid().ToString('N'))
function Assert-UserBin([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Invoke-UserBinState($Operation,[string]$State) {
  try { $output = @(Invoke-RidePlan @(Get-RideSingleOperationPlan $Operation.Id -Action Set -State $State) -Confirm:$false) }
  catch { if ($_.Exception.Message -match 'Run ID: ([a-f0-9]{32})') { $runs.Add($Matches[1]) }; throw }
  $ids = @($output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: ' })
  Assert-UserBin ($ids.Count -eq 1) 'Expected one recoverable saved run.'
  $id = $ids[0] -replace '^Run ID: ',''; $runs.Add($id); return $id
}
function Read-UserBinStartup($Operation,[string]$Initial,[switch]$NoProfile) {
  $outputPath = Join-Path $evidence ([guid]::NewGuid().ToString('N') + '.json')
  $code = '@{Path=$env:Path;Host=$Host.Name;OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Profile=[string]$PROFILE} | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath ' + "'" + $outputPath.Replace("'","''") + "'"
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
  $arguments = @('-NoLogo','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded)
  if ($NoProfile) { $arguments = @('-NoProfile') + $arguments }
  $oldPath = $env:Path
  try { $env:Path = $Initial; & $runtimes[$Operation.ProfileRuntime] @arguments | Out-Null; Assert-UserBin ($LASTEXITCODE -eq 0) 'Startup process failed.' }
  finally { $env:Path = $oldPath }
  $result = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
  Assert-UserBin ($result.Host -ceq 'ConsoleHost' -and $result.OwnerSid -ceq $owner) 'Startup host or intended-user identity mismatch.'
  Assert-UserBin ($result.Profile -ieq $originals[$Operation.Id].Path) 'Startup profile differs from the captured intended-user profile.'
  return $result
}
try {
  foreach ($op in $operations) {
    $before = Get-RideCurrentState $op; $originals[$op.Id] = $before
    Assert-UserBin ($before.Available -and $before.OwnerSid -ceq $owner) 'Runtime discovery did not resolve the intended user.'
    $plan = @(Get-RideSingleOperationPlan $op.Id -Action Set -State Enabled)
    Invoke-RidePlan $plan -WhatIf -Confirm:$false | Out-Null
    Assert-UserBin ((Get-RideCurrentState $op).FileBase64 -ceq $before.FileBase64) 'Preview changed profile bytes.'
    $run = Invoke-UserBinState $op Enabled
    Assert-UserBin ('No changes were needed; no state record was created.' -in @(Invoke-RidePlan $plan -Confirm:$false)) 'Repeat apply was not a no-op.'
    $initial = 'C:\Windows;C:\Windows\System32'
    Assert-UserBin ((Read-UserBinStartup $op $initial).Path -ceq $initial) 'Missing bin changed PATH or unrelated startup code interfered.'
    $null = New-Item -ItemType Directory -Path $bin; $ownsBin = $true
    [IO.File]::WriteAllText($sentinel,'preserve fixture contents')
    Assert-UserBin ((Read-UserBinStartup $op $initial).Path -ceq ($initial+';'+$bin)) 'Startup failed to append the existing bin.'
    $duplicate = $initial + ';"' + $bin.ToUpperInvariant() + '\"'
    Assert-UserBin ((Read-UserBinStartup $op $duplicate).Path -ceq $duplicate) 'Equivalent existing entry was rewritten or duplicated.'
    Assert-UserBin ((Read-UserBinStartup $op $initial -NoProfile).Path -ceq $initial) 'NoProfile unexpectedly applied the block.'
    $unset = Invoke-UserBinState $op Default
    Assert-UserBin ((Read-UserBinStartup $op $initial).Path -ceq $initial) 'Default retained the startup override.'
    Restore-RideRun $unset -Confirm:$false | Out-Null; $null = $runs.Remove($unset)
    Assert-UserBin ((Read-UserBinStartup $op $initial).Path -ceq ($initial+';'+$bin)) 'Restore did not recover the enabled block.'
    Restore-RideRun $run -Confirm:$false | Out-Null; $null = $runs.Remove($run)
    $after = Get-RideCurrentState $op
    Assert-UserBin ($after.FileExists -eq $before.FileExists -and $after.FileBase64 -ceq $before.FileBase64) 'Exact prior-profile restore failed.'
    Assert-UserBin ([IO.File]::ReadAllText($sentinel) -ceq 'preserve fixture contents') 'Lifecycle changed bin contents.'
    $rows.Add([pscustomobject]@{Operation=$op.Id;OwnerSid=$owner;Profile=$before.Path;RunId=$run;Status='Passed'})
    Remove-Item -LiteralPath $sentinel
    [IO.Directory]::Delete($bin,$false); $ownsBin = $false
  }
} catch { $failure = $_.Exception.Message; throw }
finally {
  $errors = @()
  for ($i=$runs.Count-1; $i -ge 0; $i--) { try { Restore-RideRun $runs[$i] -Confirm:$false | Out-Null } catch { $errors += $_.Exception.Message } }
  foreach ($op in $operations) { if ($originals.ContainsKey($op.Id)) {
    $after = Get-RideCurrentState $op; $before = $originals[$op.Id]
    if ($after.FileExists -ne $before.FileExists -or $after.FileBase64 -cne $before.FileBase64) { $errors += 'Profile recovery mismatch: '+$op.Id }
  } }
  if ($ownsBin) { try {
    if ([IO.File]::Exists($sentinel) -and [IO.File]::ReadAllText($sentinel) -ceq 'preserve fixture contents') { Remove-Item -LiteralPath $sentinel }
    [IO.Directory]::Delete($bin,$false)
  } catch { $errors += 'Fixture directory retained: '+$_.Exception.Message } }
  @{Rows=$rows.ToArray();PrimaryFailure=$failure;RecoveryErrors=$errors} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'user-bin-result.json') -Encoding UTF8
  if ($errors.Count) { throw ('Recovery failed: '+($errors -join '; ')) }
}
$rows.ToArray()
