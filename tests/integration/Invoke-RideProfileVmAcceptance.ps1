<#
.SYNOPSIS
  Run focused profile acceptance using a registered disposable VM and PowerShell Direct.
.DESCRIPTION
  Locks the idle registered controller, verifies VM/checkpoint identities, stages a
  hash-checked checkout, prepares guest PS7/UAC, reboots if needed, and runs focused
  lifecycle/Terminal acceptance. Collects evidence before unconditional checkpoint
  recovery. Does not refresh controller binaries, install host software or change host UAC.
.PARAMETER ConfigurationPath
  Existing installed RIDE controller configuration.json identifying a disposable VM.
.PARAMETER Credential
  Guest administrator credential; never exported or placed in process arguments.
.PARAMETER OutputDirectory
  Caller-owned root for one newly generated run directory and retained source/evidence.
.PARAMETER PowerShellArtifactPath
  Optional publisher acquisition JSON containing a local Path, official release Uri
  and Sha256. Verified Microsoft-signed MSI is staged only as a guest prerequisite.
.PARAMETER Version
  Print the version without accessing a VM.
.EXAMPLE
  .\Invoke-RideProfileVmAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  Correlated result JSON and evidence under OutputDirectory.
.NOTES
  Compatibility: Windows PowerShell 5.1/PowerShell 7 on a Windows Hyper-V host.
  Prerequisites: Existing idle disposable RIDE controller; Hyper-V/PowerShell Direct access.
  Guest prerequisites: Existing signed-in unlocked desktop and Windows Terminal.
  Recovery: Finally restores only the pinned VM/checkpoint; failures retain source/evidence.
  Author: RIDE-Windows maintainers. Version: 0.1.1.
  Changelog: 0.1.1: Remove host UAC observations and comparison; retain guest-specific acceptance.
    0.1.0: Add checkpoint-backed focused profile acceptance.
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([string]$ConfigurationPath, [pscredential]$Credential, [string]$OutputDirectory, [string]$PowerShellArtifactPath, [switch]$Version)
$script:ScriptVersion = '0.1.1'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $ConfigurationPath -or -not $Credential -or -not $OutputDirectory) { throw 'ConfigurationPath, Credential and OutputDirectory are required.' }
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
$config = Read-RideAutomationConfiguration $ConfigurationPath
$artifact = $null
if ($PowerShellArtifactPath) {
  $artifact = Get-Content -LiteralPath $PowerShellArtifactPath -Raw | ConvertFrom-Json
  if ($artifact.Uri -cnotmatch '^https://github\.com/PowerShell/PowerShell/releases/download/v[0-9.]+/PowerShell-[0-9.]+-win-x64\.msi$' -or
      $artifact.Sha256 -notmatch '^[0-9a-fA-F]{64}$' -or (Get-FileHash -LiteralPath $artifact.Path -Algorithm SHA256).Hash -ine $artifact.Sha256) { throw 'Invalid PowerShell publisher acquisition evidence.' }
  $signature = Get-AuthenticodeSignature -LiteralPath $artifact.Path
  if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'PowerShell prerequisite must have a valid Microsoft signature.' }
}
if (-not $config.IsDisposable -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $config.HostAccountSid) { throw 'Use the existing disposable controller in its owning account.' }
$root = Split-Path -Parent ([IO.Path]::GetFullPath($ConfigurationPath))
$lock = $null; $session = $null; $vm = $null; $checkpoint = $null; $started = $false
$runId = [guid]::NewGuid().ToString('N')
$output = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) $runId
$guestBase = 'C:\RIDE\ProfileAcceptance\' + $runId
$guestEvidence = Join-Path $guestBase 'evidence'
$result = [ordered]@{ RunId = $runId; VM = $config.VMName; VMId = $config.VMId; CheckpointId = $config.CheckpointId; Status = 'Failed'; Error = $null; Cleanup = 'NotStarted' }
function Connect-ProfileAcceptanceGuest {
  param([datetime]$AfterBoot = [datetime]::MinValue)
  $deadline = [datetime]::UtcNow.AddMinutes(5)
  while ([datetime]::UtcNow -lt $deadline) {
    try {
      $connection = New-PSSession -VMId ([guid]$config.VMId) -Credential $Credential -ErrorAction Stop
      $boot = Invoke-Command -Session $connection { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
      if ($boot -gt $AfterBoot) { return $connection }
      Remove-PSSession $connection
    } catch { }
    Start-Sleep -Seconds 3
  }
  throw 'Disposable guest PowerShell Direct did not become ready.'
}
try {
  $lock = [IO.File]::Open((Join-Path $root 'runtime/worker.lock'),'Open','Read','None')
  $vm = Get-VM -Id ([guid]$config.VMId)
  $matches = @(Get-VMSnapshot -VMName $vm.Name | Where-Object { $_.Id.ToString() -ceq $config.CheckpointId })
  if ($vm.Name -cne $config.VMName -or $vm.State -ne 'Off' -or $matches.Count -ne 1 -or $matches[0].Name -cne $config.CheckpointName -or
      (Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $config.Name).State -ne 'Ready' -or (Test-Path -LiteralPath (Join-Path $root 'runtime/blocked.json')) -or
      @(Get-ChildItem -LiteralPath (Join-Path $root 'queue/pending') -File).Count -or @(Get-ChildItem -LiteralPath (Join-Path $root 'queue/running') -File).Count) { throw 'Idle disposable VM/controller/checkpoint preflight failed.' }
  $checkpoint = $matches[0]
  if (-not $PSCmdlet.ShouldProcess($config.VMName, 'Run profile acceptance and recover the pinned clean checkpoint')) { return }
  $null = New-Item -Path $output -ItemType Directory
  Copy-RideAutomationSnapshot -Source $config.LocalRepositoryPath -Destination (Join-Path $output 'source') | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $output 'source-manifest.json') -Encoding UTF8
  Restore-VMSnapshot -VMSnapshot $checkpoint -Confirm:$false
  Start-VM -VM $vm; $started = $true
  $session = Connect-ProfileAcceptanceGuest
  Invoke-Command -Session $session -ArgumentList $guestBase,$config.VMName {
    param($Base,$Expected)
    if ($env:COMPUTERNAME -ine $Expected -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine') { throw 'Guest identity/model mismatch.' }
    $null = New-Item -Path $Base -ItemType Directory
  }
  Copy-Item -LiteralPath (Join-Path $output 'source') -Destination $guestBase -ToSession $session -Recurse
  $guestArtifact = $null
  if ($artifact) {
    $guestArtifact = Join-Path $guestBase 'powershell-artifact.json'
    $guestMsi = Join-Path $guestBase ([IO.Path]::GetFileName($artifact.Path))
    Copy-Item -LiteralPath $artifact.Path -Destination $guestMsi -ToSession $session
    Invoke-Command -Session $session -ArgumentList $artifact,$guestMsi,$guestArtifact {
      param($Artifact,$Msi,$Evidence)
      $Artifact.Path = $Msi
      $Artifact | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Evidence -Encoding UTF8
    }
  }
  $guestScript = Join-Path $guestBase 'source/tests/integration/Invoke-RideProfileAcceptance.ps1'
  $prepared = Invoke-Command -Session $session -ArgumentList $guestScript,$config.VMName,$guestEvidence,$guestArtifact {
    param($Script,$Expected,$Evidence,$Artifact)
    $env:RIDE_INTEGRATION_VM = '1'
    & $Script -Stage Prepare -ExpectedComputerName $Expected -EvidencePath $Evidence -PrerequisiteEvidencePath $Artifact -DisposableVm -Confirm:$false
  }
  $prepared | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $output 'prerequisites.json') -Encoding UTF8
  if ($prepared.RebootRequired) {
    $boot = Invoke-Command -Session $session { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
    try { Invoke-Command -Session $session { Restart-Computer -Force } } catch { }
    Remove-PSSession $session -ErrorAction SilentlyContinue; $session = $null
    Start-Sleep -Seconds 15
    $session = Connect-ProfileAcceptanceGuest -AfterBoot $boot
  }
  Invoke-Command -Session $session -ArgumentList $guestScript,$config.VMName,$guestEvidence {
    param($Script,$Expected,$Evidence)
    $env:RIDE_INTEGRATION_VM = '1'
    $log = Join-Path $Evidence 'acceptance.log'
    & (Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe') -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script -Stage Run -ExpectedComputerName $Expected -EvidencePath $Evidence -DisposableVm *> $log
    if ($LASTEXITCODE -ne 0) { throw 'Guest profile acceptance failed; collect acceptance.log and worker evidence.' }
  }
  $result.Status = 'Passed'
} catch { $result.Error = $_.Exception.Message }
finally {
  try {
    if ($session -and (Invoke-Command -Session $session -ArgumentList $guestEvidence { param($Path) Test-Path -LiteralPath $Path } -ErrorAction SilentlyContinue)) {
      Copy-Item -LiteralPath $guestEvidence -Destination $output -FromSession $session -Recurse
      # Fully finish the remote pipeline before reusing this session for copying.
      # A piped ForEach-Object can begin Copy-Item while Invoke-Command is Busy.
      $statePaths = @(Invoke-Command -Session $session {
        $path = Join-Path $env:LOCALAPPDATA 'RIDE/State'
        if (Test-Path -LiteralPath $path) { $path }
      })
      foreach ($statePath in $statePaths) { Copy-Item -LiteralPath $statePath -Destination (Join-Path $output 'saved-state') -FromSession $session -Recurse }
    }
  } catch { $result.Error = [string]$result.Error + '; Collection: ' + $_.Exception.Message; $result.Status = 'Failed' }
  try {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    if ($started) {
      $current = Get-VM -Id ([guid]$config.VMId)
      if ($current.Name -cne $config.VMName -or $checkpoint.Id.ToString() -cne $config.CheckpointId) { throw 'Cleanup identity mismatch.' }
      if ($current.State -ne 'Off') { Stop-VM -VM $current -TurnOff -Force -Confirm:$false }
      Restore-VMSnapshot -VMSnapshot $checkpoint -Confirm:$false
      $result.Cleanup = 'ResetAndOff'
    }
  } catch { $result.Cleanup = 'Failed'; $result.Status = 'Failed'; $result.Error = [string]$result.Error + '; Cleanup: ' + $_.Exception.Message }
  if (Test-Path -LiteralPath $output) { $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'result.json') -Encoding UTF8 }
  if ($lock) { $lock.Dispose() }
}
[pscustomobject]$result
if ($result.Status -ne 'Passed') { throw ($result.Error + ' Evidence: ' + $output) }
