<#
.SYNOPSIS
  Collect a read-only T480 readiness report for RIDE acceptance planning.
.DESCRIPTION
  Records bounded Windows and hardware readiness facts in a Markdown report.
  Does not modify Windows state, enable BitLocker, create a restore point,
  change firmware, or invoke RIDE handlers.
.PARAMETER OutputDirectory
  Directory for the generated report. Defaults to the current user's TEMP folder.
.EXAMPLE
  .\tests\integration\Invoke-RideT480Preflight.ps1
.EXAMPLE
  .\tests\integration\Invoke-RideT480Preflight.ps1 -OutputDirectory .\t480-results
.INPUTS
  None.
.OUTPUTS
  String. Path to the generated Markdown report.
.NOTES
  Compatibility: Windows PowerShell 5.1 on Windows 11.
  Prerequisites: Run on the intended T480. Some read-only hardware queries may
  return unavailable without elevation or firmware support; unknown is reported
  as unknown and is never treated as a pass.
  Recovery: Read-only; no recovery action is performed.
  Version: 0.1.0.
  Changelog: 0.1.0: Initial T480 read-only acceptance preflight.
#>
[CmdletBinding()]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$OutputDirectory = $env:TEMP
)

$ErrorActionPreference = 'Stop'

function ConvertTo-ReportValue {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return 'Unknown' }
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return 'Unknown' }
  return ($text -replace '[\r\n|]+', ' ')
}

function Get-ReadOnlyObservation {
  param([scriptblock]$Query)
  try {
    $value = & $Query
    if ($null -eq $value) { return 'Unknown (no value returned)' }
    return ($value | Out-String -Width 240).Trim()
  }
  catch {
    return ('Unavailable ({0})' -f $_.Exception.GetType().Name)
  }
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$processor = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
$systemDrive = $env:SystemDrive
$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $systemDrive) | Select-Object -First 1
$memoryGb = if ($computer.TotalPhysicalMemory) { [math]::Round($computer.TotalPhysicalMemory / 1GB, 1) } else { $null }
$diskTotalGb = if ($disk.Size) { [math]::Round($disk.Size / 1GB, 1) } else { $null }
$diskFreeGb = if ($disk.FreeSpace) { [math]::Round($disk.FreeSpace / 1GB, 1) } else { $null }
$osCaption = ConvertTo-ReportValue $os.Caption
$edition = if ($osCaption -match 'Windows 11 Pro') { 'Windows 11 Pro' } else { $osCaption }

$tpm = Get-ReadOnlyObservation { Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated }
$secureBoot = Get-ReadOnlyObservation { Confirm-SecureBootUEFI }
$virtualization = Get-ReadOnlyObservation {
  [pscustomobject]@{
    HypervisorPresent = $computer.HypervisorPresent
    VirtualizationFirmwareEnabled = $processor.VirtualizationFirmwareEnabled
    SecondLevelAddressTranslationExtensions = $processor.SecondLevelAddressTranslationExtensions
    VMMonitorModeExtensions = $processor.VMMonitorModeExtensions
  }
}
$wslFeatures = Get-ReadOnlyObservation {
  if (-not (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
    return 'Get-WindowsOptionalFeature is unavailable'
  }
  foreach ($featureName in @('Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform')) {
    Get-WindowsOptionalFeature -Online -FeatureName $featureName |
      Select-Object FeatureName, State
  }
}
$bitLocker = Get-ReadOnlyObservation {
  if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    return 'Get-BitLockerVolume is unavailable'
  }
  Get-BitLockerVolume -MountPoint $systemDrive |
    Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage
}
$restorePoints = Get-ReadOnlyObservation {
  if (-not (Get-Command Get-ComputerRestorePoint -ErrorAction SilentlyContinue)) {
    return 'Get-ComputerRestorePoint is unavailable'
  }
  $points = @(Get-ComputerRestorePoint | Sort-Object -Property CreationTime -Descending)
  if ($points.Count -eq 0) { return 'No restore point returned by the query' }
  'Count: {0}; latest sequence: {1}; latest creation time: {2}' -f $points.Count, $points[0].SequenceNumber, $points[0].CreationTime
}

$reportLines = @(
  '# T480 RIDE preflight report',
  '',
  ('- Collected: {0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss K')),
  '- Scope: read-only readiness observations; no RIDE handler was invoked.',
  '',
  '## Target',
  '',
  ('- Manufacturer: {0}' -f (ConvertTo-ReportValue $computer.Manufacturer)),
  ('- Model: {0}' -f (ConvertTo-ReportValue $computer.Model)),
  ('- Windows edition: {0}' -f $edition),
  ('- Windows version/build: {0} / {1}' -f (ConvertTo-ReportValue $os.Version), (ConvertTo-ReportValue $os.BuildNumber)),
  ('- CPU: {0}' -f (ConvertTo-ReportValue $processor.Name)),
  ('- Physical memory: {0} GB' -f (ConvertTo-ReportValue $memoryGb)),
  ('- System drive: {0}; total {1} GB; free {2} GB' -f $systemDrive, (ConvertTo-ReportValue $diskTotalGb), (ConvertTo-ReportValue $diskFreeGb)),
  '',
  '## Security and recovery readiness',
  '',
  ('- TPM: {0}' -f (ConvertTo-ReportValue $tpm)),
  ('- Secure Boot: {0}' -f (ConvertTo-ReportValue $secureBoot)),
  ('- Virtualization capability: {0}' -f (ConvertTo-ReportValue $virtualization)),
  ('- WSL/Virtual Machine Platform Windows feature state: {0}' -f (ConvertTo-ReportValue $wslFeatures)),
  ('- BitLocker OS-volume observation: {0}' -f (ConvertTo-ReportValue $bitLocker)),
  ('- System restore-point observation: {0}' -f (ConvertTo-ReportValue $restorePoints)),
  '',
  '## Interpretation',
  '',
  '- Unknown or unavailable observations require review; they are not passes.',
  '- This report contains no BitLocker recovery key, serial number, or account name.',
  '- A restore point does not establish BitLocker recovery readiness.',
  '- No firmware, encryption, boot, or other Windows setting was changed.',
  ''
)

$resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-Path -LiteralPath $resolvedOutputDirectory -PathType Container)) {
  New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
}
$reportName = 't480-ride-preflight-{0}.md' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
$reportPath = Join-Path $resolvedOutputDirectory $reportName
Set-Content -LiteralPath $reportPath -Value $reportLines -Encoding UTF8
Write-Output ('Preflight report: {0}' -f $reportPath)
