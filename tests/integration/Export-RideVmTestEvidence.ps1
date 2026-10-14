<#
.SYNOPSIS
  Collect partial guest evidence after an unsuccessful task-controlled VM run.

.DESCRIPTION
  - Reads saved RIDE state and guest logs; never invokes RIDE handlers or tests.
  - The worker bounds this collector to 90 seconds before checkpoint recovery.
  Copies evidence into the guest result directory and back to the host.
  Copies files independently and records unavailable files in collection-omissions.json.
  Reuses byte-identical files already exported by the main runner to avoid repeating
  hundreds of remoting transfers after a reported guest failure.

.PARAMETER ConfigurationPath
  Installed pinned controller configuration.json.

.PARAMETER RunId
  32 lowercase hexadecimal request ID used to select C:\RIDE\TestResults\<RunId> in the guest.

.PARAMETER ResultDirectory
  Host request-result directory receiving the guest evidence subdirectory.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.PARAMETER VerifyGitHubCredentialAbsence
  Bounded post-reset probe: start the pinned guest, verify the request's credential
  is absent under the delivery identity, and save nonsecret evidence. The parent
  controller must restore the checkpoint again in finally, including on timeout.

.EXAMPLE
  .\tests\integration\Export-RideVmTestEvidence.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None. Copies guest evidence and saved state to the correlated host result directory.

.NOTES
  Compatibility: 64-bit Windows PowerShell 5.1 with AutomatedLab 5.61.0.
  Prerequisites: Guest is still reachable; unavailable evidence is reported without preventing
  reset.
  File/environment inputs: Fixed installed configuration and a correlated test request ID.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 0.5.0
  Changelog:
    0.5.0: Add explicit GitHub PAT selection and credential-safe acceptance boundaries.
    - 0.4.1: Log collection and session-teardown timing for bounded failure diagnosis.
    - 0.4.0: Skip byte-identical exported evidence while preserving changed and unavailable files.
    - 0.3.0: Preserve readable partial evidence when another file is locked.
  - 0.2.0: Collect observations from the configured guest repository after failure.
    - 0.1.0: Initial bounded failure-evidence collection.
  Internal bounded collector. It writes evidence directories but does not invoke RIDE handlers or
  integration scenarios.

.LINK
  tests/integration/automatedlab-tasks.md

.LINK
  tests/integration/automatedlab.md

#>


[CmdletBinding()]
param([string] $ConfigurationPath, [ValidatePattern('^[0-9a-f]{32}$')][string] $RunId, [string] $ResultDirectory, [switch] $VerifyGitHubCredentialAbsence, [switch] $Version)
$script:ScriptVersion = '0.5.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
function Copy-RidePartialGuestEvidence {
  param($Session, [string]$GuestPath, [string]$Destination)
  $prefix=$GuestPath.TrimEnd('\')+'\'
  $files=@(Invoke-Command -Session $Session -ArgumentList $GuestPath -ScriptBlock {
    param($Path)
    foreach ($file in Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction Stop) {
      try {
        [pscustomobject]@{ Path = $file.FullName; SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash; Error = $null }
      }
      catch { [pscustomobject]@{ Path = $file.FullName; SHA256 = $null; Error = $_.Exception.Message } }
    }
  } -ErrorAction Stop)
  $omissions=New-Object System.Collections.Generic.List[object]
  foreach($file in $files){
    if(-not $file.Path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'Guest evidence path escaped the correlated result directory.'}
    $relative=$file.Path.Substring($prefix.Length)
    if(@($relative -split '\\' | Where-Object {$_ -in @('.','..')}).Count){throw 'Unsafe guest evidence relative path.'}
    $target=Join-Path $Destination $relative
    if ($file.Error) {
      $omissions.Add([pscustomobject]@{ Path = $relative; Error = $file.Error })
      Write-Warning "Partial evidence unavailable: $relative"
      continue
    }
    if ([string]$file.SHA256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid guest evidence SHA-256.' }
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    try {
      if ((Test-Path -LiteralPath $target -PathType Leaf) -and
          (Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash -eq $file.SHA256) { continue }
      Copy-Item -LiteralPath $file.Path -Destination $target -FromSession $Session -Force -ErrorAction Stop
    }
    catch{$omissions.Add([pscustomobject]@{Path=$relative;Error=$_.Exception.Message});Write-Warning "Partial evidence unavailable: $relative"}
  }
  ConvertTo-Json -InputObject @($omissions.ToArray()) -Depth 4 | Set-Content -LiteralPath (Join-Path $Destination 'collection-omissions.json') -Encoding UTF8
}
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
$config = Read-RideAutomationConfiguration $ConfigurationPath
$null = Assert-RideAutomationHost $config
$null = Import-RideAutomationLab $config
$session = $null
try {
  if ($VerifyGitHubCredentialAbsence) { Start-VM -VM (Get-VM -Id ([guid]$config.VMId) -ErrorAction Stop) -ErrorAction Stop | Out-Null }
  $retries = if ($VerifyGitHubCredentialAbsence) { 15 } else { 1 }
  $session = New-LabPSSession -ComputerName $config.VMName -Retries $retries -Interval 2
  if ($VerifyGitHubCredentialAbsence) {
    $receiptPath = Join-Path $ResultDirectory 'guest-authentication.json'
    $expectedSid = if (Test-Path -LiteralPath $receiptPath) { (Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json).WindowsSid } else { '' }
    $absent = Invoke-Command -Session $session -ArgumentList @($RunId, $expectedSid) -ScriptBlock {
      param($Id, $ExpectedSid)
      $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
      if ($ExpectedSid -and $ExpectedSid -ne $sid) { throw 'Recovered guest identity differs from credential delivery.' }
      $path = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('RIDE\TransientCredentials\' + $Id + '\credential.json')
      [pscustomobject]@{ RunId = $Id; WindowsSid = $sid; CredentialAbsent = -not (Test-Path -LiteralPath $path) }
    } -ErrorAction Stop
    if ($absent.RunId -ne $RunId -or $absent.CredentialAbsent -ne $true) { throw 'Recovered guest credential absence check failed.' }
    $null = New-Item -ItemType Directory -Path (Join-Path $ResultDirectory 'guest') -Force
    $absent | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ResultDirectory 'guest\credential-recovery.json') -Encoding UTF8
    return
  }
  $guestPath = "C:\RIDE\TestResults\$RunId"
  Invoke-Command -Session $session -ArgumentList @($guestPath, $config.GuestRepositoryPath) -ScriptBlock {
    param($Path, $RepositoryPath)
    $ErrorActionPreference = 'Stop'
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $observations = Join-Path $RepositoryPath 'catalog\artifact-observations.json'
    if (Test-Path -LiteralPath $observations) { Copy-Item -LiteralPath $observations -Destination (Join-Path $Path 'artifact-observations.json') -Force }
    foreach ($scope in @('Machine', 'User')) {
      $base = if ($scope -eq 'Machine') { [Environment]::GetFolderPath('CommonApplicationData') } else { [Environment]::GetFolderPath('LocalApplicationData') }
      $source = Join-Path $base 'RIDE\State'
      if (Test-Path -LiteralPath $source) {
        $destination = Join-Path $Path "state\$scope"
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Get-ChildItem -LiteralPath $source -Force | Where-Object Name -NotIn @('Cache', 'Artifacts') | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force }
      }
    }
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Path 'partial-guest.json') -Encoding UTF8
  } -ErrorAction Stop
  $destination = Join-Path $ResultDirectory 'guest'
  New-Item -ItemType Directory -Path $destination -Force | Out-Null
  Write-Output ("{0:o} Beginning partial guest evidence copy." -f [datetime]::UtcNow)
  Copy-RidePartialGuestEvidence -Session $session -GuestPath $guestPath -Destination $destination
  Write-Output ("{0:o} Partial guest evidence copy complete." -f [datetime]::UtcNow)
}
finally {
  if ($session) {
    Write-Output ("{0:o} Closing guest session." -f [datetime]::UtcNow)
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    Write-Output ("{0:o} Guest session closed." -f [datetime]::UtcNow)
  }
}
