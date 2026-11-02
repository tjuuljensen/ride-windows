<#
.SYNOPSIS
  Record read-only Defender evidence for disposable package acceptance.
.DESCRIPTION
  Requires active real-time antivirus and records detection identifiers since
  guest boot. Never changes exclusions, restores quarantined files or scans paths.
.NOTES
  Windows PowerShell 5.1 and PowerShell 7 on Windows. Version: 0.2.0.
  Changelog: 0.2.0: Include threat names and resource categories without private paths.
    0.1.0: Add explicit package acceptance observations without payload access.
#>
$ErrorActionPreference = 'Stop'

function Get-RideDefenderAcceptanceObservation {
  <#
  .SYNOPSIS
    Read active protection and sanitized detections for a bounded guest interval.
  .PARAMETER Since
    Start of the disposable guest interval, including initial payload staging.
  .EXAMPLE
    Get-RideDefenderAcceptanceObservation -Since (Get-Date).AddMinutes(-10)
  .OUTPUTS
    Protection booleans, threat names and detection IDs/timestamps/categories;
    no resource paths or file reads.
  .NOTES
    Read-only. Provider errors fail closed; unavailable evidence is not a pass.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][datetime]$Since)
  if($Since.ToUniversalTime() -gt [datetime]::UtcNow){throw 'Defender interval starts in the future.'}
  $status=Get-MpComputerStatus -ErrorAction Stop
  $detections=@(Get-MpThreatDetection -ErrorAction Stop | Where-Object {
    $_.InitialDetectionTime -ge $Since -or $_.LastThreatStatusChangeTime -ge $Since
  } | ForEach-Object {
    $categories=@($_.Resources | ForEach-Object {
      if($_ -match '(?i)(?:^|file:_)[a-z]:\\Windows\\System32\\drivers\\etc\\hosts$'){'WindowsHostsFile'}
      elseif($_ -match '(?i)\\RIDE\\PortableAcceptance\\[0-9a-f]{32}\\source\\'){'StagedSource'}
      elseif($_ -match '(?i)\\RIDE\\PortableAcceptance\\[0-9a-f]{32}\\payloads\\'){'StagedPayload'}
      else{'Other'}
    } | Sort-Object -Unique)
    [pscustomobject]@{DetectionId=[string]$_.DetectionID;ThreatId=[string]$_.ThreatID;
      InitialDetectionTime=$_.InitialDetectionTime;LastThreatStatusChangeTime=$_.LastThreatStatusChangeTime;ResourceCategories=$categories}
  })
  $threats=@(Get-MpThreat -ErrorAction Stop | Where-Object IsActive | ForEach-Object {
    [pscustomobject]@{ThreatId=[string]$_.ThreatID;ThreatName=[string]$_.ThreatName;IsActive=$true}
  })
  $active=@($threats | ForEach-Object {$_.ThreatId})
  [pscustomobject]@{ObservedAtUtc=[datetime]::UtcNow.ToString('o');SinceUtc=$Since.ToUniversalTime().ToString('o');
    AMServiceEnabled=[bool]$status.AMServiceEnabled;AntivirusEnabled=[bool]$status.AntivirusEnabled;
    RealTimeProtectionEnabled=[bool]$status.RealTimeProtectionEnabled;ActiveThreatIds=$active;ActiveThreats=$threats;Detections=$detections;
    Passed=([bool]$status.AMServiceEnabled -and [bool]$status.AntivirusEnabled -and [bool]$status.RealTimeProtectionEnabled -and $active.Count -eq 0 -and $detections.Count -eq 0);
    ExclusionsChanged=$false;PayloadsAccessed=$false}
}
Export-ModuleMember -Function Get-RideDefenderAcceptanceObservation
