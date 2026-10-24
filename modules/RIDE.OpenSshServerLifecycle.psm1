<#
.SYNOPSIS
  Apply and restore an explicitly selected OpenSSH Server service/firewall state.
.DESCRIPTION
  Uses the read-only OpenSSH Server observer, a protected machine-scope snapshot,
  ShouldProcess, literal post-state verification and conflict-aware restore. It does
  not install/remove the Windows capability or delete generated host keys/configuration.
.PARAMETER ExpectedComputerName
  Local computer name to compare with the fresh observation.
.PARAMETER ExpectedBuild
  Exact Windows build expected for this candidate.
.PARAMETER ExpectedEditionId
  Exact Windows EditionID expected for this candidate.
.PARAMETER StartupType
  Explicit desired sshd startup type. The service is started as a separate effect.
.PARAMETER InboundRuleState
  Keep, enable or disable the exact existing local OpenSSH inbound firewall rule.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Existing elevation, Windows 11 or Windows Server 2025 candidate, installed capability.
  Recovery: Restores the captured service status/start mode and exact rule enabled state when literal state has not drifted.
  Host keys or configuration created on first start are retained; this is not exact data recovery.
  This source candidate is not connected to the catalog or a supported target.
  Version: 0.1.0.
  Changelog: 0.1.0: Add guarded OpenSSH Server activation and service/firewall restore candidate.
.LINK
  ../docs/windows-component-inventory.md#openssh-server-component-boundary
#>
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.OpenSshServerObservation.psm1') -ErrorAction Stop

function Get-RideOpenSshServerActivationStateDirectory {
  Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RIDE/State/OpenSshServerActivation'
}

function Initialize-RideOpenSshServerActivationStateDirectory {
  $root = Get-RideOpenSshServerActivationStateDirectory
  New-Item -ItemType Directory -Path $root -Force | Out-Null
  $item = Get-Item -LiteralPath $root -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'OpenSSH Server state directory cannot be a reparse point.' }
  $acl = Get-Acl -LiteralPath $root
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleAll($rule) }
  foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
    $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
    $access = [Security.AccessControl.FileSystemAccessRule]::new(
      $sid,
      [Security.AccessControl.FileSystemRights]::FullControl,
      [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
      [Security.AccessControl.PropagationFlags]::None,
      [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($access)
  }
  Set-Acl -LiteralPath $root -AclObject $acl
  $root
}

function Test-RideOpenSshServerActivationPendingReboot {
  foreach ($path in @(
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
  )) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $false)
    if ($key) { $key.Dispose(); return $true }
  }
  $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager', $false)
  if (-not $key) { throw 'Unable to inspect pending file-rename servicing state.' }
  try { $pending = $key.GetValue('PendingFileRenameOperations', $null) } finally { $key.Dispose() }
  return [bool](@($pending | Where-Object { $_ }).Count)
}

function Test-RideOpenSshServerActivationAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RideOpenSshActivationFreshState {
  param([string]$ExpectedComputerName, [string]$ExpectedBuild, [string]$ExpectedEditionId)
  $state = Get-RideOpenSshServerState -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId
  $providers = @{}
  foreach ($provider in $state.Providers) { $providers[[string]$provider.Name] = $provider }
  foreach ($required in @('Capability', 'Service', 'Firewall', 'ServerData')) {
    if (-not $providers.ContainsKey($required) -or $providers[$required].Status -eq 'Unavailable') {
      throw "OpenSSH Server $required observation is unavailable; refusing activation."
    }
  }
  if ($state.WindowsContext.NativeProcess -ne $true -or [long]$state.WindowsContext.Build -lt 22000 -or [string]$state.WindowsContext.ProductType -cnotin @('WinNT', 'ServerNT')) {
    throw 'OpenSSH Server activation candidate supports only native Windows 11 or Windows Server 2025 builds.'
  }
  if ($providers.Capability.Observation.State -cne 'Installed') { throw 'OpenSSH Server capability must already be installed; servicing is a separate workflow.' }
  if ($providers.Service.Status -cne 'Captured' -or $providers.Service.Observation.Name -cne 'sshd') { throw 'OpenSSH Server service is not present with the exact sshd identity.' }
  $service = $providers.Service.Observation
  if ([string]$service.State -cnotin @('Running', 'Stopped') -or [string]$service.StartMode -cnotin @('Auto', 'Manual', 'Disabled') -or [string]::IsNullOrWhiteSpace([string]$service.StartName)) {
    throw 'OpenSSH Server service state is not a supported literal value.'
  }
  if ($providers.Firewall.Status -cnotin @('Captured', 'NotFound')) { throw 'OpenSSH Server firewall state is ambiguous.' }
  if ($providers.Firewall.Status -ceq 'Captured') { Assert-RideOpenSshServerFirewallIdentity $providers.Firewall.Observation }
  if ($providers.ServerData.Status -cnotin @('Captured', 'NotFound')) { throw 'OpenSSH Server data inventory is unavailable.' }
  [pscustomobject]@{
    Observation = $state
    Context = $state.WindowsContext
    Capability = $providers.Capability.Observation
    Service = $providers.Service.Observation
    Firewall = $providers.Firewall.Observation
    FirewallStatus = [string]$providers.Firewall.Status
    ServerData = $providers.ServerData.Observation
  }
}

function Assert-RideOpenSshServerFirewallIdentity {
  param([Parameter(Mandatory)]$Firewall)
  if ($Firewall.Name -cne 'OpenSSH-Server-In-TCP' -or $Firewall.Direction -cne 'Inbound' -or $Firewall.Action -cne 'Allow' -or
      $Firewall.Protocol -cne 'TCP' -or $Firewall.LocalPort -cne '22' -or $Firewall.Profile -cnotin @('Any', 'Domain, Private, Public') -or
      $Firewall.PolicyStoreSourceType -cne 'Local' -or $Firewall.PolicyStoreSource -cnotin @('PersistentStore', 'Local')) {
    throw 'OpenSSH Server firewall rule differs from the exact local TCP/22 rule; refusing to change it.'
  }
  if ([string]$Firewall.Enabled -cnotin @('True', 'False')) { throw 'OpenSSH Server firewall enabled state is not a literal Boolean.' }
}

function Save-RideOpenSshServerActivationSnapshot {
  param([Parameter(Mandatory)]$Record)
  $root = Initialize-RideOpenSshServerActivationStateDirectory
  $runId = [guid]::NewGuid().ToString('N')
  $path = Join-Path $root ($runId + '.json')
  $json = ConvertTo-Json -InputObject $Record -Depth 12 -Compress
  $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
  if ($bytes.Length -gt 65536) { throw 'OpenSSH Server activation snapshot exceeds 64 KiB.' }
  $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  [pscustomobject]@{ RunId = $runId; Path = $path }
}

function Read-RideOpenSshServerActivationSnapshot {
  param([Parameter(Mandatory)][string]$RunId)
  if ($RunId -notmatch '^[0-9a-fA-F]{32}$') { throw 'RunId must be a 32-character hexadecimal saved component ID.' }
  $path = Join-Path (Get-RideOpenSshServerActivationStateDirectory) ($RunId + '.json')
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Saved OpenSSH Server activation state was not found.' }
  $item = Get-Item -LiteralPath $path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 65536) { throw 'Saved OpenSSH Server state path or size is invalid.' }
  $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
  try {
    $bytes = [byte[]]::new([int]$stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) { $count = $stream.Read($bytes, $offset, $bytes.Length - $offset); if ($count -le 0) { throw 'Saved OpenSSH Server state changed while being read.' }; $offset += $count }
  } finally { $stream.Dispose() }
  $record = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json -ErrorAction Stop
  if ($record.SchemaVersion -ne 1 -or $record.Kind -cne 'OpenSshServerActivationState' -or $record.Name -cne 'sshd' -or
      $record.CapabilityName -cne 'OpenSSH.Server~~~~0.0.1.0' -or $record.DesiredStartupType -cnotin @('Manual', 'Automatic') -or
      $record.DesiredInboundRuleState -cnotin @('Keep', 'Enabled', 'Disabled') -or $record.ProductType -cnotin @('WinNT', 'ServerNT') -or
      [long]$record.Build -lt 22000 -or $record.BeforeService.State -cnotin @('Running', 'Stopped') -or
      $record.BeforeService.StartMode -cnotin @('Auto', 'Manual', 'Disabled') -or
      $record.DesiredService.State -cne 'Running' -or
      $record.DesiredService.StartMode -cne $(if ($record.DesiredStartupType -ceq 'Automatic') { 'Auto' } else { 'Manual' }) -or
      $record.DesiredService.StartName -cne $record.BeforeService.StartName -or
      $record.BeforeFirewall.Status -cnotin @('Captured', 'NotFound')) {
    throw 'Saved OpenSSH Server state does not match the supported identity and schema.'
  }
  if ($record.BeforeFirewall.Status -ceq 'Captured') {
    Assert-RideOpenSshServerFirewallIdentity $record.BeforeFirewall.Observation
    $expectedFirewall = if ($record.DesiredInboundRuleState -ceq 'Keep') { [string]$record.BeforeFirewall.Observation.Enabled } else { [string]($record.DesiredInboundRuleState -ceq 'Enabled') }
    if ($record.DesiredFirewallEnabled -cne $expectedFirewall) { throw 'Saved OpenSSH Server firewall intent does not match its prior state and requested action.' }
  } else {
    if ($record.BeforeFirewall.Observation -ne $null -or $record.DesiredInboundRuleState -cne 'Keep' -or $record.DesiredFirewallEnabled -ne $null) { throw 'Saved OpenSSH Server firewall state is inconsistent.' }
  }
  $record
}

function Get-RideOpenSshServerDataChanged {
  param($Before, $After)
  if ([string]$Before.Status -cne [string]$After.Status) { return $true }
  if ($Before.Status -cne 'Captured') { return $false }
  $beforeFiles = @($Before.Files | Sort-Object Name)
  $afterFiles = @($After.Files | Sort-Object Name)
  if ($beforeFiles.Count -ne $afterFiles.Count) { return $true }
  for ($index = 0; $index -lt $beforeFiles.Count; $index++) {
    if ($beforeFiles[$index].Name -cne $afterFiles[$index].Name -or $beforeFiles[$index].Length -ne $afterFiles[$index].Length -or $beforeFiles[$index].Sha256 -cne $afterFiles[$index].Sha256) { return $true }
  }
  return $false
}

function Invoke-RideOpenSshServerActivation {
  <#
  .SYNOPSIS
    Explicitly start sshd and optionally enable/disable its exact existing inbound rule.
  .DESCRIPTION
    Does not install the capability. Requires the exact target identity and fresh state,
    stores prior service/firewall literals before mutation, and retains generated host
    keys/configuration when the service is first started.
  .PARAMETER ExpectedComputerName
    Local computer expected by the operator.
  .PARAMETER ExpectedBuild
    Exact Windows build expected by the operator.
  .PARAMETER ExpectedEditionId
    Exact Windows EditionID expected by the operator.
  .PARAMETER StartupType
    Explicit service startup mode, Manual or Automatic.
  .PARAMETER InboundRuleState
    Explicitly keep, enable or disable the exact pre-existing local OpenSSH rule.
  .EXAMPLE
    Invoke-RideOpenSshServerActivation -ExpectedComputerName $env:COMPUTERNAME -ExpectedBuild 26100 -ExpectedEditionId Professional -StartupType Manual -InboundRuleState Keep -WhatIf
  .NOTES
    No service activation or Windows target support is established by this unregistered candidate.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
    [Parameter(Mandatory)][ValidateSet('Manual', 'Automatic')][string]$StartupType,
    [Parameter(Mandatory)][ValidateSet('Keep', 'Enabled', 'Disabled')][string]$InboundRuleState
  )
  if (-not (Test-RideOpenSshServerActivationAdministrator)) { throw 'OpenSSH Server activation requires an already elevated administrator session.' }
  if (Test-RideOpenSshServerActivationPendingReboot) { throw 'A servicing restart is pending; defer OpenSSH Server activation.' }
  $fresh = Get-RideOpenSshActivationFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
  if ($InboundRuleState -cne 'Keep' -and $fresh.FirewallStatus -cne 'Captured') { throw 'The exact local OpenSSH firewall rule must already exist before changing its enabled state.' }
  $beforeService = [ordered]@{ State = [string]$fresh.Service.State; StartMode = [string]$fresh.Service.StartMode; StartName = [string]$fresh.Service.StartName }
  $beforeFirewall = if ($fresh.FirewallStatus -ceq 'Captured') { [ordered]@{ Status = 'Captured'; Observation = $fresh.Firewall } } else { [ordered]@{ Status = 'NotFound'; Observation = $null } }
  $beforeServerData = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $fresh.ServerData -Depth 10 -Compress)
  $desiredFirewallEnabled = if ($InboundRuleState -ceq 'Keep') { if ($beforeFirewall.Status -ceq 'Captured') { [string]$fresh.Firewall.Enabled } else { $null } } else { [string]($InboundRuleState -ceq 'Enabled') }
  $alreadyApplied = $fresh.Service.State -ceq 'Running' -and $fresh.Service.StartMode -ceq $(if ($StartupType -ceq 'Automatic') { 'Auto' } else { 'Manual' }) -and
    ($InboundRuleState -ceq 'Keep' -or [string]$fresh.Firewall.Enabled -ceq $desiredFirewallEnabled)
  if ($alreadyApplied) { return [pscustomobject]@{ Status = 'AlreadyApplied'; ServiceState = $fresh.Service.State; StartupType = $fresh.Service.StartMode; InboundRuleState = $desiredFirewallEnabled; RunId = $null; PostStateVerified = $true; ServerDataChanged = $false } }
  $effectiveFirewallState = if ($fresh.FirewallStatus -ceq 'Captured') { $desiredFirewallEnabled } else { 'NotFound' }
  if (-not $PSCmdlet.ShouldProcess("$ExpectedComputerName / OpenSSH Server", "Start sshd with $StartupType startup and local TCP/22 inbound rule enabled='$effectiveFirewallState'")) {
    return [pscustomobject]@{ Status = 'WhatIf'; ServiceState = $fresh.Service.State; StartupType = $fresh.Service.StartMode; InboundRuleState = if ($fresh.FirewallStatus -ceq 'Captured') { $fresh.Firewall.Enabled } else { 'NotFound' }; InboundAccessWillBeAllowed = ($fresh.FirewallStatus -ceq 'Captured' -and $desiredFirewallEnabled -ceq 'True'); RunId = $null; PostStateVerified = $false; ServerDataChanged = $false }
  }
  $record = [ordered]@{
    SchemaVersion = 1; Kind = 'OpenSshServerActivationState'; Name = 'sshd'; CapabilityName = 'OpenSSH.Server~~~~0.0.1.0'
    ComputerName = [string]$fresh.Context.ComputerName; Build = [string]$fresh.Context.Build; EditionId = [string]$fresh.Context.EditionId
    UpdateBuildRevision = [long]$fresh.Context.UpdateBuildRevision; ProductType = [string]$fresh.Context.ProductType
    BeforeService = $beforeService; DesiredService = [ordered]@{ State = 'Running'; StartMode = $(if ($StartupType -ceq 'Automatic') { 'Auto' } else { 'Manual' }); StartName = [string]$fresh.Service.StartName }
    BeforeFirewall = $beforeFirewall; DesiredFirewallEnabled = $desiredFirewallEnabled
    DesiredStartupType = $StartupType; DesiredInboundRuleState = $InboundRuleState
    BeforeServerData = $beforeServerData; ExactHostKeyOrConfigurationRecovery = $false
  }
  $saved = Save-RideOpenSshServerActivationSnapshot $record
  try {
    if ($InboundRuleState -ceq 'Disabled' -and $fresh.Firewall.Enabled -ceq 'True') {
      Set-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -Enabled 'False' -ErrorAction Stop
    }
    if ($fresh.Service.StartMode -cne $record.DesiredService.StartMode) { Set-Service -Name 'sshd' -StartupType $StartupType -ErrorAction Stop }
    if ($fresh.Service.State -cne 'Running') { Start-Service -Name 'sshd' -ErrorAction Stop }
    if ($InboundRuleState -ceq 'Enabled' -and $fresh.Firewall.Enabled -cne 'True') {
      Set-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -Enabled 'True' -ErrorAction Stop
    }
  } catch {
    throw "OpenSSH Server activation failed after saving recovery run '$($saved.RunId)'. Inspect state and use Restore-RideOpenSshServerActivation if it matches the saved or requested literals. $($_.Exception.Message)"
  }
  $after = Get-RideOpenSshActivationFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
  $serviceMatches = $after.Service.State -ceq 'Running' -and $after.Service.StartMode -ceq $record.DesiredService.StartMode -and $after.Service.StartName -ceq $beforeService.StartName
  $firewallMatches = $InboundRuleState -ceq 'Keep' -or ($after.FirewallStatus -ceq 'Captured' -and $after.Firewall.Enabled -ceq $desiredFirewallEnabled)
  [pscustomobject]@{
    Status = if ($serviceMatches -and $firewallMatches) { 'Applied' } else { 'AppliedPostStateMismatch' }
    ServiceState = [string]$after.Service.State; StartupType = [string]$after.Service.StartMode
    InboundRuleState = if ($after.FirewallStatus -ceq 'Captured') { [string]$after.Firewall.Enabled } else { 'NotFound' }
    InboundAccessWillBeAllowed = ($after.FirewallStatus -ceq 'Captured' -and $after.Firewall.Enabled -ceq 'True')
    RunId = $saved.RunId; SnapshotPath = $saved.Path; PostStateVerified = ($serviceMatches -and $firewallMatches)
    ServerDataChanged = Get-RideOpenSshServerDataChanged $beforeServerData $after.ServerData
    ExactHostKeyOrConfigurationRecovery = $false
  }
}

function Restore-RideOpenSshServerActivation {
  <#
  .SYNOPSIS
    Restore captured sshd startup/running state and the exact firewall enabled state.
  .DESCRIPTION
    Refuses target or literal drift. It never deletes host keys/configuration created
    on first start and reports whether the bounded server-data inventory changed.
  .PARAMETER RunId
    Saved 32-character hexadecimal activation run ID.
  .PARAMETER ExpectedComputerName
    Local computer expected by the operator.
  .PARAMETER ExpectedBuild
    Exact Windows build expected by the operator.
  .PARAMETER ExpectedEditionId
    Exact Windows EditionID expected by the operator.
  .EXAMPLE
    Restore-RideOpenSshServerActivation -RunId $runId -ExpectedComputerName $env:COMPUTERNAME -ExpectedBuild 26100 -ExpectedEditionId Professional -WhatIf
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId
  )
  $record = Read-RideOpenSshServerActivationSnapshot $RunId
  if ($record.ComputerName -ine $ExpectedComputerName -or $record.Build -cne $ExpectedBuild -or $record.EditionId -ine $ExpectedEditionId) { throw 'Saved OpenSSH Server activation state belongs to another target.' }
  if (-not (Test-RideOpenSshServerActivationAdministrator)) { throw 'OpenSSH Server restoration requires an already elevated administrator session.' }
  if (Test-RideOpenSshServerActivationPendingReboot) { throw 'A servicing restart is pending; defer OpenSSH Server restoration.' }
  $fresh = Get-RideOpenSshActivationFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
  if ([long]$fresh.Context.UpdateBuildRevision -ne [long]$record.UpdateBuildRevision -or [string]$fresh.Context.ProductType -cne [string]$record.ProductType) { throw 'OpenSSH Server target servicing revision or product type changed; the saved state was retained.' }
  $currentService = [ordered]@{ State = [string]$fresh.Service.State; StartMode = [string]$fresh.Service.StartMode; StartName = [string]$fresh.Service.StartName }
  $serviceIsBefore = ($currentService.State -ceq $record.BeforeService.State -and $currentService.StartMode -ceq $record.BeforeService.StartMode -and $currentService.StartName -ceq $record.BeforeService.StartName)
  $serviceStateAllowed = $currentService.State -cin @([string]$record.BeforeService.State, [string]$record.DesiredService.State)
  $serviceModeAllowed = $currentService.StartMode -cin @([string]$record.BeforeService.StartMode, [string]$record.DesiredService.StartMode)
  if (-not $serviceStateAllowed -or -not $serviceModeAllowed -or $currentService.StartName -cne $record.BeforeService.StartName) { throw 'OpenSSH Server service state drifted from saved and requested literals; refusing restore.' }
  $firewallIsBefore = $record.BeforeFirewall.Status -ceq $fresh.FirewallStatus -and ($fresh.FirewallStatus -cne 'Captured' -or $fresh.Firewall.Enabled -ceq $record.BeforeFirewall.Observation.Enabled)
  $firewallIsDesired = if ($record.DesiredInboundRuleState -ceq 'Keep') { $firewallIsBefore } else { $fresh.FirewallStatus -ceq 'Captured' -and $fresh.Firewall.Enabled -ceq $record.DesiredFirewallEnabled }
  if (-not $firewallIsBefore -and -not $firewallIsDesired) { throw 'OpenSSH Server firewall state drifted from both saved and requested literals; refusing restore.' }
  if ($serviceIsBefore -and $firewallIsBefore) {
    return [pscustomobject]@{ Status = 'AlreadyRestored'; RunId = $RunId; ServiceRestored = $true; FirewallRestored = $true; ServerDataChanged = Get-RideOpenSshServerDataChanged $record.BeforeServerData $fresh.ServerData; ServerDataCleanupPerformed = $false; PostStateVerified = $true }
  }
  if (-not $PSCmdlet.ShouldProcess("$ExpectedComputerName / OpenSSH Server / $RunId", 'Restore captured sshd and firewall state')) {
    return [pscustomobject]@{ Status = 'WhatIf'; RunId = $RunId; ServiceRestored = $false; FirewallRestored = $false; ServerDataChanged = Get-RideOpenSshServerDataChanged $record.BeforeServerData $fresh.ServerData; ServerDataCleanupPerformed = $false; PostStateVerified = $false }
  }
  if (-not $firewallIsBefore -and $record.BeforeFirewall.Status -ceq 'Captured') {
    Set-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -Enabled ([string]$record.BeforeFirewall.Observation.Enabled) -ErrorAction Stop
  }
  if (-not $serviceIsBefore) {
    $restoreStartupType = switch -CaseSensitive ([string]$record.BeforeService.StartMode) { 'Auto' { 'Automatic' } 'Manual' { 'Manual' } 'Disabled' { 'Disabled' } default { throw 'Saved sshd startup type is not supported.' } }
    Set-Service -Name 'sshd' -StartupType $restoreStartupType -ErrorAction Stop
    if ($record.BeforeService.State -ceq 'Running' -and $fresh.Service.State -cne 'Running') { Start-Service -Name 'sshd' -ErrorAction Stop }
    if ($record.BeforeService.State -ceq 'Stopped' -and $fresh.Service.State -cne 'Stopped') { Stop-Service -Name 'sshd' -ErrorAction Stop }
  }
  $after = Get-RideOpenSshActivationFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
  $serviceRestored = $after.Service.State -ceq $record.BeforeService.State -and $after.Service.StartMode -ceq $record.BeforeService.StartMode -and $after.Service.StartName -ceq $record.BeforeService.StartName
  $firewallRestored = $record.BeforeFirewall.Status -ceq $after.FirewallStatus -and ($after.FirewallStatus -cne 'Captured' -or $after.Firewall.Enabled -ceq $record.BeforeFirewall.Observation.Enabled)
  [pscustomobject]@{
    Status = if ($serviceRestored -and $firewallRestored) { 'Restored' } else { 'RestorePostStateMismatch' }
    RunId = $RunId; ServiceRestored = $serviceRestored; FirewallRestored = $firewallRestored
    ServerDataChanged = Get-RideOpenSshServerDataChanged $record.BeforeServerData $after.ServerData
    ServerDataCleanupPerformed = $false; PostStateVerified = ($serviceRestored -and $firewallRestored)
  }
}

Export-ModuleMember -Function Invoke-RideOpenSshServerActivation, Restore-RideOpenSshServerActivation
