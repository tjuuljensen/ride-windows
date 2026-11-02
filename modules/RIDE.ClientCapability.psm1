<#
.SYNOPSIS
  Inspect and service the catalog OpenSSH Client capability.
.DESCRIPTION
  Uses the catalog's declared Windows Update servicing route. Captures no payload;
  restore recovers the saved literal capability state conditionally through DISM.
  Does not change servicing policy, user SSH data, services, firewall or reboot state.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Existing elevation for servicing; Windows 11 client candidate only.
  State: The engine saves a version-2 capability snapshot before invoking the writer.
  Recovery: Matching target/revision and unchanged expected state are required.
  Windows Update availability and exact prior payload/version are not guaranteed.
  Version: 0.1.0.
  Changelog: 0.1.0: Add source-explicit catalog lifecycle and conditional recovery.
.LINK
  ../docs/windows-component-inventory.md
#>
$ErrorActionPreference = 'Stop'

function Assert-RideClientCapabilityOperation {
  param([hashtable]$Operation)
  if ($Operation.Id -cne 'component.openssh-client-capability' -or
      $Operation.Handler -cne 'ClientCapability' -or $Operation.Kind -cne 'WindowsCapability' -or
      $Operation.CapabilityName -cne 'OpenSSH.Client~~~~0.0.1.0' -or
      $Operation.ServicingSource -cne 'WindowsUpdate' -or $Operation.Scope -cne 'Machine') {
    throw 'Unrecognized client capability identity or servicing source.'
  }
}

function Get-RideClientCapabilityContext {
  $version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $product = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -ErrorAction Stop
  [pscustomobject]@{
    ComputerName = [Environment]::MachineName; Build = [string]$version.CurrentBuildNumber
    EditionId = [string]$version.EditionID; UpdateBuildRevision = $version.UBR
    InstallationType = [string]$version.InstallationType; ProductType = [string]$product.ProductType
    NativeProcess = ([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)
  }
}

function Assert-RideClientCapabilityContext {
  param($Context)
  foreach ($field in @('ComputerName','Build','EditionId','InstallationType','ProductType')) {
    if ($Context.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($Context.$field) -or
        $Context.$field.Length -gt 255 -or $Context.$field -match '[\x00-\x1f]') { throw 'Invalid client capability target identity.' }
  }
  if ($Context.Build -cnotmatch '^[0-9]{4,8}$' -or [long]$Context.Build -lt 22000 -or
      $Context.ProductType -cne 'WinNT' -or $Context.InstallationType -cne 'Client' -or
      $Context.NativeProcess -isnot [bool] -or -not $Context.NativeProcess -or
      ($Context.UpdateBuildRevision -isnot [int] -and $Context.UpdateBuildRevision -isnot [long] -and $Context.UpdateBuildRevision -isnot [uint32]) -or
      $Context.UpdateBuildRevision -lt 0 -or $Context.UpdateBuildRevision -gt [uint32]::MaxValue) {
    throw 'Client capability servicing requires a native Windows 11 client identity and valid revision.'
  }
}

function Get-RideClientCapabilityNativeState {
  param([string]$Name)
  Dism\Get-WindowsCapability -Online -Name $Name -ErrorAction Stop
}

function Get-RideClientCapabilityState {
  <#
  .SYNOPSIS
    Inspect the exact catalog capability without invoking a servicing writer.
  .PARAMETER Operation
    Catalog OpenSSH Client operation with the declared WindowsUpdate source.
  .OUTPUTS
    PSCustomObject. Availability, literal capability state and local target identity.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable]$Operation)
  Assert-RideClientCapabilityOperation $Operation
  try {
    $context = Get-RideClientCapabilityContext
    Assert-RideClientCapabilityContext $context
    $rows = @(Get-RideClientCapabilityNativeState -Name $Operation.CapabilityName)
    if ($rows.Count -ne 1 -or [string]$rows[0].Name -cne $Operation.CapabilityName) { throw 'Expected one exact client capability observation.' }
    $state = [string]$rows[0].State
    if ($state -cnotin @('Installed','NotPresent')) { throw "Client capability has a pending or unknown state: $state" }
    [pscustomobject]@{Available=$true;Reason=$null;Present=($state -ceq 'Installed');CapabilityState=$state;Observation=[pscustomobject]@{WindowsContext=$context;CapabilityName=$Operation.CapabilityName;ServicingSource=$Operation.ServicingSource}}
  } catch {
    [pscustomobject]@{Available=$false;Reason=$_.Exception.Message;Present=$false;CapabilityState=$null;Observation=$null}
  }
}

function Test-RideClientCapabilityAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
  finally { $identity.Dispose() }
}

function Test-RideClientCapabilityPendingReboot {
  foreach ($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
    if (Test-Path -LiteralPath $path -ErrorAction Stop) { return $true }
  }
  $session = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
  return [bool](@($session.PendingFileRenameOperations | Where-Object { $_ }).Count)
}

function Assert-RideClientCapabilitySameTarget {
  param($Expected,$Actual)
  Assert-RideClientCapabilityContext $Expected
  Assert-RideClientCapabilityContext $Actual
  foreach ($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','InstallationType','ProductType','NativeProcess')) {
    if ($Expected.$field -cne $Actual.$field) { throw "Client capability target drift ($field); saved state retained." }
  }
}

function Invoke-RideClientCapabilityNativeChange {
  param([string]$Name,[string]$DesiredState)
  if ($DesiredState -ceq 'Installed') {
    # No Source or LimitAccess override: the catalog explicitly permits Windows
    # Update and configured servicing sources. Never edit machine source policy.
    Dism\Add-WindowsCapability -Online -Name $Name -ErrorAction Stop
  } elseif ($DesiredState -ceq 'NotPresent') {
    Dism\Remove-WindowsCapability -Online -Name $Name -ErrorAction Stop
  } else { throw 'Invalid literal capability target state.' }
}

function Set-RideClientCapabilityState {
  <#
  .SYNOPSIS
    Apply one catalog capability state after the engine saves prior state.
  .PARAMETER Operation
    Exact catalog client capability with declared Windows Update acquisition.
  .PARAMETER State
    Present or Absent. Removal recovery may require reacquisition from Windows Update.
  .PARAMETER ExpectedState
    Captured current state; target/revision and literal state must still match.
  .OUTPUTS
    PSCustomObject. Verified result and DISM restart indication; never restarts Windows.
  .NOTES
    Internal engine handler. The caller owns durable pre-change capture and run reporting.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][hashtable]$Operation,
    [Parameter(Mandatory)][ValidateSet('Present','Absent')][string]$State,
    [Parameter(Mandatory)]$ExpectedState)
  Assert-RideClientCapabilityOperation $Operation
  if (-not $ExpectedState.Available -or $ExpectedState.CapabilityState -cnotin @('Installed','NotPresent') -or
      $ExpectedState.Observation.CapabilityName -cne $Operation.CapabilityName -or
      $ExpectedState.Observation.ServicingSource -cne $Operation.ServicingSource) { throw 'Invalid captured client capability state/source.' }
  $current = Get-RideClientCapabilityState $Operation
  if (-not $current.Available) { throw "Client capability unavailable: $($current.Reason)" }
  Assert-RideClientCapabilitySameTarget $ExpectedState.Observation.WindowsContext $current.Observation.WindowsContext
  if ($current.CapabilityState -cne $ExpectedState.CapabilityState) { throw 'Client capability state drifted; refusing change.' }
  $desired = if ($State -eq 'Present') { 'Installed' } else { 'NotPresent' }
  if ($current.CapabilityState -ceq $desired) { return [pscustomobject]@{Status='AlreadyDesired';CapabilityState=$desired;RestartNeeded=$false;ExactPayloadRecoverySupported=$false} }
  if (-not $WhatIfPreference -and -not (Test-RideClientCapabilityAdministrator)) { throw 'Client capability servicing requires existing elevation.' }
  if (Test-RideClientCapabilityPendingReboot) { throw 'A Windows servicing restart is pending; no capability change was attempted.' }
  if (-not $PSCmdlet.ShouldProcess($Operation.CapabilityName,"Set $desired using the declared Windows Update servicing route; recovery is conditional")) { return }
  $result = Invoke-RideClientCapabilityNativeChange -Name $Operation.CapabilityName -DesiredState $desired
  $after = Get-RideClientCapabilityState $Operation
  if (-not $after.Available -or $after.CapabilityState -cne $desired) { throw 'DISM did not reach the requested literal state; inspect servicing/restart status and retain the saved run for recovery.' }
  Assert-RideClientCapabilitySameTarget $current.Observation.WindowsContext $after.Observation.WindowsContext
  $restart = $null
  if ($result -and $result.PSObject.Properties['RestartNeeded']) { $restart = [bool]$result.RestartNeeded }
  if ($restart) { Write-Warning 'DISM reports a restart is needed. RIDE did not restart Windows; complete servicing before another change.' }
  [pscustomobject]@{Status='Applied';CapabilityState=$after.CapabilityState;RestartNeeded=$restart;ExactPayloadRecoverySupported=$false}
}

function Restore-RideClientCapabilityState {
  <#
  .SYNOPSIS
    Restore the literal capability state from an engine version-2 snapshot.
  .PARAMETER Operation
    Original catalog capability identity and source policy.
  .PARAMETER Snapshot
    Engine snapshot with before/expected state, source and exact target identity.
  .PARAMETER ValidateOnly
    Validate recovery identity and live state without invoking a writer or confirmation.
  .OUTPUTS
    PSCustomObject. AlreadyRestored or the verified servicing result.
  .NOTES
    Reinstallation is conditional on configured sources/Windows Update and is not
    exact prior-version recovery. Legacy ClientComponentState records use their original reader.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][hashtable]$Operation,[Parameter(Mandatory)]$Snapshot,[switch]$ValidateOnly)
  Assert-RideClientCapabilityOperation $Operation
  if ($Snapshot.SnapshotVersion -ne 2 -or $Snapshot.OperationId -cne $Operation.Id -or
      $Snapshot.CapabilityName -cne $Operation.CapabilityName -or $Snapshot.ServicingSource -cne $Operation.ServicingSource -or
      $Snapshot.CapabilityState -cnotin @('Installed','NotPresent') -or $Snapshot.ExpectedState -cnotin @('Installed','NotPresent')) {
    throw 'Invalid client capability recovery identity, source or state.'
  }
  $current = Get-RideClientCapabilityState $Operation
  if (-not $current.Available) { throw "Client capability unavailable for recovery: $($current.Reason)" }
  Assert-RideClientCapabilitySameTarget $Snapshot.WindowsContext $current.Observation.WindowsContext
  if ($current.CapabilityState -ceq $Snapshot.CapabilityState) { return [pscustomobject]@{Status='AlreadyRestored';CapabilityState=$current.CapabilityState;RestartNeeded=$false;ExactPayloadRecoverySupported=$false} }
  if ($current.CapabilityState -cne $Snapshot.ExpectedState) { throw 'Client capability recovery state drifted; saved state retained.' }
  if ($ValidateOnly) { return }
  $state = if ($Snapshot.CapabilityState -ceq 'Installed') { 'Present' } else { 'Absent' }
  if (-not $PSCmdlet.ShouldProcess($Operation.CapabilityName,'Restore captured literal capability state; payload recovery is conditional')) { return }
  Set-RideClientCapabilityState -Operation $Operation -State $state -ExpectedState $current -WhatIf:$WhatIfPreference -Confirm:$false
}

Export-ModuleMember -Function Get-RideClientCapabilityState,Set-RideClientCapabilityState,Restore-RideClientCapabilityState
