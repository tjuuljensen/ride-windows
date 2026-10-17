<#
.SYNOPSIS
  Prepare and exercise PowerShell profile settings in a disposable Windows guest.
.DESCRIPTION
  Prepare acquires the catalog's signed PowerShell MSI as a test prerequisite and
  enables guest UAC for normal/elevated-token acceptance. Run tests real discovered
  profiles, engine capture, repeat apply, default/unset and conflict recovery, then
  invokes interactive Terminal probes. Candidate support is enabled only in the
  test process's catalog; production metadata is unchanged. The outer VM runner
  must collect evidence and restore the pinned checkpoint, including prerequisites.
.PARAMETER Stage
  Prepare or Run (default). Prepare reports whether a guest reboot is required.
.PARAMETER ExpectedComputerName
  Exact disposable guest identity attested by the host runner.
.PARAMETER EvidencePath
  Guest-owned evidence directory beneath C:\RIDE\ProfileAcceptance.
.PARAMETER DisposableVm
  Explicit disposable-guest attestation; required before mutations.
.PARAMETER PrerequisiteEvidencePath
  Optional host-staged publisher acquisition JSON for a hash-verified signed MSI.
.PARAMETER Version
  Print the version without inspecting or changing a guest.
.EXAMPLE
  .\Invoke-RideProfileAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  System.Object. Prerequisite status and correlated lifecycle/Terminal evidence.
.NOTES
  Compatibility: Windows PowerShell 5.1, disposable Windows 11/Server 2025 desktop guests.
  Prerequisites: Elevated guest, RIDE_INTEGRATION_VM=1, signed-in unlocked desktop.
  Sources: Catalog Microsoft PowerShell publisher MSI; no host software/UAC changes.
  Recovery: Saved runs plus unconditional outer clean-checkpoint recovery.
  Author: RIDE-Windows maintainers. Version: 0.1.1.
  Changelog: 0.1.1: Keep color acceptance scoped away from other profile renderers.
    0.1.0: Add real profile and interactive color acceptance.
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [ValidateSet('Prepare','Run')][string]$Stage = 'Run',
  [string]$ExpectedComputerName,
  [string]$EvidencePath,
  [string]$PrerequisiteEvidencePath,
  [switch]$DisposableVm,
  [switch]$Version
)
$script:ScriptVersion = '0.1.1'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $DisposableVm -or $env:RIDE_INTEGRATION_VM -ne '1' -or -not $ExpectedComputerName -or
    $env:COMPUTERNAME -ine $ExpectedComputerName -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine') { throw 'Use the attested disposable VM host runner; no workstation integration is permitted.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'An elevated disposable-guest coordinator is required.' }
$evidence = [IO.Path]::GetFullPath($EvidencePath)
if (-not $evidence.StartsWith('C:\RIDE\ProfileAcceptance\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence must remain beneath the disposable guest acceptance directory.' }
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE-ProfileSettings.psm1') -Global
$target = Get-RidePlatform
if ($target -notin @('Windows 11','Windows Server 2025')) { throw 'Unsupported acceptance guest.' }
if (-not $PSCmdlet.ShouldProcess($ExpectedComputerName, "$Stage profile acceptance in the disposable guest")) { return }
$null = New-Item -Path $evidence -ItemType Directory -Force

if ($Stage -eq 'Prepare') {
  $powerShell = Join-Path $env:ProgramFiles 'PowerShell/7/pwsh.exe'
  $artifact = $null
  $missingRuntime = $null
  if (-not [IO.File]::Exists($powerShell)) {
    $operation = (Get-RideCatalog).Operations | Where-Object { $_.ProfileSetting -eq 'TerminalColors' -and $_.ProfileRuntime -eq 'PowerShell7' }
    $missingRuntime = Get-RideProfileSettingState $operation
    if ($missingRuntime.Available -or $missingRuntime.Path) { throw 'Absent PowerShell 7 was not reported as unavailable before prerequisite setup.' }
    if ($PrerequisiteEvidencePath) {
      $base = (Split-Path -Parent $evidence) + '\'
      if (-not [IO.Path]::GetFullPath($PrerequisiteEvidencePath).StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) { throw 'Prerequisite evidence must belong to this guest run.' }
      $artifact = Get-Content -LiteralPath $PrerequisiteEvidencePath -Raw | ConvertFrom-Json
      if (-not [IO.Path]::GetFullPath($artifact.Path).StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or
          $artifact.Uri -cnotmatch '^https://github\.com/PowerShell/PowerShell/releases/download/v[0-9.]+/PowerShell-[0-9.]+-win-x64\.msi$' -or
          $artifact.Sha256 -notmatch '^[0-9a-fA-F]{64}$' -or (Get-FileHash -LiteralPath $artifact.Path -Algorithm SHA256).Hash -ine $artifact.Sha256) { throw 'Invalid guest prerequisite publisher/hash evidence.' }
    } else {
      $artifact = Save-RidePackage -Id package.powershell -Destination (Join-Path (Split-Path -Parent $evidence) 'prerequisites') -Confirm:$false
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $artifact.Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'PowerShell prerequisite MSI signature is not valid Microsoft publisher evidence.' }
    # Prerequisite setup is not acceptance of the PowerShell package operation on Server.
    $installer = Start-Process -FilePath msiexec.exe -ArgumentList @('/i', ('"' + $artifact.Path + '"'), '/qn', '/norestart', 'ADD_PATH=1') -WindowStyle Hidden -PassThru -Wait
    if ($installer.ExitCode -notin @(0,3010) -or -not [IO.File]::Exists($powerShell)) { throw 'Disposable PowerShell prerequisite installation failed.' }
  }
  $policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $uac = (Get-ItemProperty -LiteralPath $policy -Name EnableLUA).EnableLUA
  if ($uac -ne 1) { Set-ItemProperty -LiteralPath $policy -Name EnableLUA -Value 1 }
  $result = [pscustomobject]@{ Computer = $env:COMPUTERNAME; Target = $target; PowerShell = $powerShell; Artifact = $artifact; MissingRuntime = $missingRuntime; PreviousGuestUac = $uac; RebootRequired = ($uac -ne 1) }
  $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $evidence 'prerequisites.json') -Encoding UTF8
  $result
  return
}

$env:PATH = (Join-Path $env:ProgramFiles 'PowerShell/7') + ';' + $env:PATH
$catalog = Get-RideCatalog
$operations = @($catalog.Operations | Where-Object ProfileSetting -eq 'TerminalColors')
if ($operations.Count -ne 2) { throw 'Expected exactly the two color acceptance operations.' }
foreach ($operation in $operations) {
  if ($target -notin $operation.CandidateTargets -and $target -notin $operation.SupportedTargets) { throw 'Guest is not a declared candidate or supported target.' }
  $operation.SupportedTargets = @($target); $operation.PendingAcceptance = $false
  $operation.TargetDefaults = @{ $target = @{ DefaultValue = 'Default'; EffectiveDefault = 'No RIDE startup override; configured Terminal appearance' } }
}
& (Get-Module RIDE.Engine) { param($Catalog) $script:RideLibraryContext = @{ Catalog = $Catalog; Libraries = @(); ProfileFiles = @() } } $catalog
$rows = [Collections.Generic.List[object]]::new()
$runs = [Collections.Generic.List[string]]::new()
$originals = @{}
$primaryFailure = $null
function Assert-ProfileAcceptance([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Invoke-ProfileAcceptanceState($Operation,[string]$State,[switch]$Unset) {
  $plan = if ($Unset) { @(Get-RideSingleOperationPlan $Operation.Id -Action Unset) } else { @(Get-RideSingleOperationPlan $Operation.Id -Action Set -State $State) }
  $output = @(Invoke-RidePlan $plan -Confirm:$false)
  $run = @($output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: ' } | Select-Object -Last 1) -replace '^Run ID: ', ''
  if ($run) { $runs.Add([string]$run[0]); return [string]$run[0] }
}
try {
  foreach ($operation in $operations) {
    Write-Host ("Lifecycle: {0}" -f $operation.ProfileRuntime)
    $original = Get-RideCurrentState $operation
    Assert-ProfileAcceptance $original.Available 'Both installed runtimes must be discovered without mocks.'
    $originals[$operation.Id] = $original
    $plan = @(Get-RideSingleOperationPlan $operation.Id -Action Set -State Recommended)
    Invoke-RidePlan $plan -WhatIf -Confirm:$false | Out-Null
    Assert-ProfileAcceptance ((Get-RideCurrentState $operation).FileBase64 -ceq $original.FileBase64) 'Preview changed profile bytes.'
    $first = Invoke-ProfileAcceptanceState $operation Recommended
    Assert-ProfileAcceptance ([bool]$first) 'Apply did not capture a run.'
    Assert-ProfileAcceptance (Test-RideDesiredState $operation Recommended) 'Recommended configuration did not apply.'
    Assert-ProfileAcceptance ('No changes were needed; no state record was created.' -in @(Invoke-RidePlan $plan -Confirm:$false)) 'Repeat apply changed configuration.'
    foreach ($state in @('AdminBlue','Default','Baseline')) {
      Write-Host ("Lifecycle state/restore: {0} {1}" -f $operation.ProfileRuntime,$state)
      $run = Invoke-ProfileAcceptanceState $operation $state
      $desired = if ($state -eq 'Baseline') { 'Default' } else { $state }
      Assert-ProfileAcceptance (Test-RideDesiredState $operation $desired) "Failed state $state."
      if ($run) { Restore-RideRun $run -Confirm:$false | Out-Null; $runs.Remove($run) | Out-Null }
      Assert-ProfileAcceptance (Test-RideDesiredState $operation Recommended) 'Saved-run restore lost the predecessor.'
    }
    $run = Invoke-ProfileAcceptanceState $operation Default -Unset
    Assert-ProfileAcceptance (Test-RideDesiredState $operation Default) 'Unset did not remove the selected block.'
    Restore-RideRun $run -WhatIf -Confirm:$false | Out-Null
    Assert-ProfileAcceptance (Test-RideDesiredState $operation Default) 'Restore preview changed the file.'
    Restore-RideRun $run -Confirm:$false | Out-Null; $runs.Remove($run) | Out-Null
    $current = Get-RideCurrentState $operation
    $attributes = [IO.File]::GetAttributes($current.Path)
    [IO.File]::SetAttributes($current.Path, ($attributes -bor [IO.FileAttributes]::ReadOnly))
    $failureRun = $null
    try {
      try { Invoke-ProfileAcceptanceState $operation AdminBlue | Out-Null; throw 'Read-only profile unexpectedly accepted a write.' }
      catch { if ($_.Exception.Message -match 'Run ID: ([a-f0-9]{32})') { $failureRun = $Matches[1] } else { throw } }
    }
    finally { [IO.File]::SetAttributes($current.Path, $attributes) }
    Assert-ProfileAcceptance ([bool]$failureRun) 'Partial failure did not retain a saved run.'
    Restore-RideRun $failureRun -Confirm:$false | Out-Null
    $rows.Add([pscustomobject]@{ Operation = $operation.Id; Runtime = $operation.ProfileRuntime; OwnerSid = $original.OwnerSid; Path = $original.Path; OriginalFileExists = $original.FileExists; Lifecycle = 'Passed'; FirstRunId = $first; FailureRunId = $failureRun })
  }
  $rows.ToArray() | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'lifecycle.json') -Encoding UTF8
  Write-Host 'Identity: redirected Documents and alternate-account isolation'
  & (Join-Path $PSScriptRoot 'Invoke-RideProfileIdentityAcceptance.ps1') -ExpectedComputerName $ExpectedComputerName -EvidencePath $evidence -DisposableVm -Confirm:$false
  # The visual worker uses the signed-in guest account, with both limited and high tokens.
  Write-Host 'Visual: limited/high tokens, startup bypass and inherited elevation'
  & (Join-Path $PSScriptRoot 'Invoke-RideProfileVisualAcceptance.ps1') -Role Coordinator -ExpectedComputerName $ExpectedComputerName -EvidencePath $evidence -DisposableVm -Confirm:$false
}
catch { $primaryFailure = $_.Exception.Message; throw }
finally {
  $recoveryErrors = @()
  for ($index = $runs.Count - 1; $index -ge 0; $index--) { try { Restore-RideRun $runs[$index] -Confirm:$false | Out-Null } catch { $recoveryErrors += $_.Exception.Message } }
  foreach ($operation in $operations) {
    if ($originals.ContainsKey($operation.Id)) {
      $after = Get-RideCurrentState $operation; $before = $originals[$operation.Id]
      if ($after.FileExists -ne $before.FileExists -or $after.FileBase64 -cne $before.FileBase64) { $recoveryErrors += 'Profile recovery mismatch: ' + $operation.Id }
    }
  }
  @{ ProfileRecovery = if ($recoveryErrors.Count) { 'Failed' } else { 'Passed' }; PrimaryFailure = $primaryFailure; Errors = $recoveryErrors } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'profile-recovery.json') -Encoding UTF8
  if ($recoveryErrors.Count) { throw ('Primary failure: ' + $primaryFailure + '; Recovery: ' + ($recoveryErrors -join '; ')) }
}
$rows.ToArray()
