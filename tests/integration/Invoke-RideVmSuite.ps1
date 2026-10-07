[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if ($env:RIDE_INTEGRATION_VM -ne '1') { throw "Set RIDE_INTEGRATION_VM=1 only inside a disposable VM before running integration checks." }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the integration suite from an elevated PowerShell session.' }

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $root 'modules/RIDE.Engine.psm1') -Force
$target = Get-RidePlatform
if ($target -notin @('Windows 11', 'Windows Server 2025')) { throw "Unsupported integration VM target: $target" }

$setting = Get-RideOperation -Id 'windows.show-known-extensions'
$original = Get-RideCurrentState -Operation $setting
$analystProfile = Get-RideProfile -Path (Join-Path $root 'profiles/analyst-basics.psd1')
$baselineProfile = Get-RideProfile -Path (Join-Path $root 'profiles/baseline.psd1')

try {
  $firstRun = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $analystProfile) -Confirm:$false | ForEach-Object { $_ })
  $runIdLine = $firstRun | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if (-not $runIdLine) { throw 'First apply did not return a run ID.' }
  $runId = $runIdLine -replace '^Run ID: ', ''

  $null = Invoke-RidePlan -Plan @(Get-RidePlan -Profile $analystProfile) -Confirm:$false
  $status = @(Get-RideStatus -Profile $analystProfile)
  if (@($status | Where-Object { -not $_.InDesiredState }).Count -gt 0) { throw 'Repeated apply did not converge to the requested profile.' }

  Restore-RideRun -RunId $runId -Confirm:$false
  $afterRestore = Get-RideCurrentState -Operation $setting
  if ([bool]$afterRestore.Exists -ne [bool]$original.Exists -or ($original.Exists -and ($afterRestore.Value -ne $original.Value -or $afterRestore.ValueType -ne $original.ValueType))) {
    throw 'Exact setting restore did not recover the initial Explorer value.'
  }

  $null = Invoke-RidePlan -Plan @(Get-RidePlan -Profile $baselineProfile) -Confirm:$false
  if (-not (Test-RideDesiredState -Operation $setting -State 'Disabled')) { throw 'Baseline profile did not set the documented Explorer state.' }

  $null = Invoke-RidePlan -Plan @(Get-RidePlan -Profile $analystProfile) -Confirm:$false
  $removePlan = @(Get-RidePlan -Profile $analystProfile -Action Remove)
  $null = Invoke-RidePlan -Plan $removePlan -Confirm:$false
  foreach ($id in @('package.7zip', 'package.notepadpp')) {
    $package = Get-RideOperation -Id $id
    if ((Get-RideCurrentState -Operation $package).Present) { throw "Package removal failed: $id" }
  }

  Write-Output "VM integration suite passed on $target. Restore the VM checkpoint before reuse."
}
catch {
  Write-Error ("VM integration suite failed on {0}: {1}" -f $target, $_.Exception.Message)
  throw
}
