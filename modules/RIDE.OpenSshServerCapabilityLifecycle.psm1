<#
.SYNOPSIS
  Install or remove the Windows OpenSSH Server capability with guarded recovery.
.DESCRIPTION
  Installs only the exact OpenSSH Server Windows capability. It never starts sshd.
  After servicing, it disables the exact TCP/22 allow rule only when installation
  created or enabled that rule from a prior absent/disabled state. Existing enabled
  firewall state is preserved. Removal requires the matching completed install
  snapshot and refuses if the service, firewall or server data has drifted. It
  supports reversal only when those surfaces were absent before installation.
  This candidate is not connected to the catalog.
.PARAMETER ExpectedComputerName
  Local target name expected by the operator.
.PARAMETER ExpectedBuild
  Exact Windows build expected by the operator.
.PARAMETER ExpectedEditionId
  Exact Windows EditionID expected by the operator.
.PARAMETER Source
  Optional servicing source directory. When omitted, Windows uses configured
  capability servicing sources.
.PARAMETER LimitAccess
  Prevent DISM from contacting Windows Update for payload content.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Existing elevation; Windows 11 or Windows Server 2025 candidate.
  Recovery: Removes the capability only to a verified NotPresent state for eligible saved runs; native acceptance is pending.
  Version: 0.2.0.
  Changelog: 0.2.0: Add saved-state removal for unchanged installations with no pre-existing server surfaces.
  Changelog: 0.1.0: Add guarded capability-install candidate with post-install firewall reconciliation.
.LINK
  ../docs/windows-component-inventory.md#openssh-server-component-boundary
#>
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.OpenSshServerObservation.psm1') -ErrorAction Stop

function Test-RideOpenSshServerInstallAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-RideOpenSshServerInstallPendingReboot {
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

function Initialize-RideOpenSshServerInstallStateDirectory {
  $root = Get-RideOpenSshServerInstallStateDirectory
  New-Item -ItemType Directory -Path $root -Force | Out-Null
  $item = Get-Item -LiteralPath $root -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'OpenSSH Server install state directory cannot be a reparse point.' }
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

function Get-RideOpenSshServerInstallStateDirectory {
  Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RIDE/State/OpenSshServerInstall'
}

function Assert-RideOpenSshServerInstallFirewallIdentity {
  param([Parameter(Mandatory)]$Firewall)
  if ($Firewall.Name -cne 'OpenSSH-Server-In-TCP' -or $Firewall.Direction -cne 'Inbound' -or $Firewall.Action -cne 'Allow' -or
      $Firewall.Protocol -cne 'TCP' -or $Firewall.LocalPort -cne '22' -or $Firewall.Profile -cnotin @('Any', 'Domain, Private, Public') -or
      $Firewall.PolicyStoreSourceType -cne 'Local' -or $Firewall.PolicyStoreSource -cnotin @('PersistentStore', 'Local')) {
    throw 'OpenSSH Server firewall rule differs from the exact local TCP/22 rule; refusing to change it.'
  }
  if ([string]$Firewall.Enabled -cnotin @('True', 'False')) { throw 'OpenSSH Server firewall rule has an invalid enabled state.' }
}

function Get-RideOpenSshServerInstallFreshState {
  param([string]$ExpectedComputerName, [string]$ExpectedBuild, [string]$ExpectedEditionId)
  $state = Get-RideOpenSshServerState -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId
  $providers = @{}
  foreach ($provider in $state.Providers) { $providers[[string]$provider.Name] = $provider }
  foreach ($required in @('Capability', 'Service', 'Firewall', 'ServerData')) {
    if (-not $providers.ContainsKey($required) -or $providers[$required].Status -eq 'Unavailable') {
      throw "OpenSSH Server $required observation is unavailable; refusing capability installation."
    }
  }
  if ($state.WindowsContext.NativeProcess -ne $true -or [long]$state.WindowsContext.Build -lt 22000 -or [string]$state.WindowsContext.ProductType -cnotin @('WinNT', 'ServerNT')) {
    throw 'OpenSSH Server installation candidate accepts only native Windows 11 or Windows Server 2025 builds.'
  }
  if ($providers.Capability.Observation.Name -cne 'OpenSSH.Server~~~~0.0.1.0' -or $providers.Capability.Observation.State -cnotin @('Installed', 'NotPresent')) {
    throw 'OpenSSH Server capability state is not an exact supported literal.'
  }
  if ($providers.Service.Status -cnotin @('Captured', 'NotFound')) { throw 'OpenSSH Server service state is ambiguous.' }
  if ($providers.Service.Status -ceq 'Captured') {
    if ($providers.Service.Observation.Name -cne 'sshd' -or $providers.Service.Observation.State -cnotin @('Running', 'Stopped') -or $providers.Service.Observation.StartMode -cnotin @('Auto', 'Manual', 'Disabled')) {
      throw 'OpenSSH Server service identity or literal state is not supported.'
    }
  }
  if ($providers.Firewall.Status -cnotin @('Captured', 'NotFound')) { throw 'OpenSSH Server firewall state is ambiguous.' }
  if ($providers.Firewall.Status -ceq 'Captured') { Assert-RideOpenSshServerInstallFirewallIdentity $providers.Firewall.Observation }
  if ($providers.ServerData.Status -cnotin @('Captured', 'NotFound')) { throw 'OpenSSH Server data inventory is unavailable.' }
  [pscustomobject]@{
    Observation = $state; Context = $state.WindowsContext
    Capability = $providers.Capability.Observation
    Service = $providers.Service.Observation; ServiceStatus = [string]$providers.Service.Status
    Firewall = $providers.Firewall.Observation; FirewallStatus = [string]$providers.Firewall.Status
    ServerData = $providers.ServerData.Observation
  }
}

function Test-RideOpenSshServerInstallDataEqual {
  param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After)
  if ($Before.Status -cne $After.Status) { return $false }
  if ($Before.Status -cne 'Captured') { return $true }
  $beforeFiles = @($Before.Files | Sort-Object Name)
  $afterFiles = @($After.Files | Sort-Object Name)
  if ($beforeFiles.Count -ne $afterFiles.Count) { return $false }
  for ($index = 0; $index -lt $beforeFiles.Count; $index++) {
    if ($beforeFiles[$index].Name -cne $afterFiles[$index].Name -or $beforeFiles[$index].Length -ne $afterFiles[$index].Length -or $beforeFiles[$index].Sha256 -cne $afterFiles[$index].Sha256) { return $false }
  }
  return $true
}

function Save-RideOpenSshServerRemovalMarker {
  param([Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$ComputerName)
  $removed = [ordered]@{
    SchemaVersion = 1
    Kind = 'OpenSshServerRemovalState'
    RunId = $RunId
    ComputerName = $ComputerName
    CapabilityState = 'NotPresent'
    RemovedAtUtc = [DateTime]::UtcNow.ToString('o')
    PostStateVerified = $true
  }
  $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes((ConvertTo-Json -InputObject $removed -Depth 4 -Compress))
  $root = Get-RideOpenSshServerInstallStateDirectory
  $path = Join-Path $root ($RunId + '-removed.json')
  $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  return $path
}

function Save-RideOpenSshServerInstallSnapshot {
  param([Parameter(Mandatory)]$Record, [string]$RunId)
  $root = Initialize-RideOpenSshServerInstallStateDirectory
  if (-not $RunId) { $RunId = [guid]::NewGuid().ToString('N') }
  if ($RunId -notmatch '^[0-9a-fA-F]{32}$') { throw 'RunId must be a 32-character hexadecimal saved component ID.' }
  $suffix = if ($Record.InstallStatus -ceq 'Completed') { '-completed.json' } else { '-install.json' }
  $path = Join-Path $root ($RunId + $suffix)
  $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes((ConvertTo-Json -InputObject $Record -Depth 12 -Compress))
  if ($bytes.Length -gt 65536) { throw 'OpenSSH Server installation snapshot exceeds 64 KiB.' }
  $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  [pscustomobject]@{ RunId = $RunId; Path = $path }
}

function Read-RideOpenSshServerInstallSnapshot {
  param([Parameter(Mandatory)][string]$RunId)
  if ($RunId -notmatch '^[0-9a-fA-F]{32}$') { throw 'RunId must be a 32-character hexadecimal saved component ID.' }
  $root = Get-RideOpenSshServerInstallStateDirectory
  $path = Join-Path $root ($RunId + '-completed.json')
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Completed OpenSSH Server installation snapshot was not found.' }
  $item = Get-Item -LiteralPath $path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 65536) { throw 'OpenSSH Server installation snapshot path or size is invalid.' }
  $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
  try {
    $bytes = [byte[]]::new([int]$stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) { $count = $stream.Read($bytes, $offset, $bytes.Length - $offset); if ($count -le 0) { throw 'OpenSSH Server installation snapshot changed while being read.' }; $offset += $count }
  } finally { $stream.Dispose() }
  $record = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json -ErrorAction Stop
  if ($record.SchemaVersion -ne 1 -or $record.Kind -cne 'OpenSshServerInstallState' -or $record.InstallStatus -cne 'Completed' -or
      $record.CapabilityName -cne 'OpenSSH.Server~~~~0.0.1.0' -or $record.BeforeCapabilityState -cne 'NotPresent' -or
      $record.AfterCapabilityState -cne 'Installed' -or $record.ProductType -cnotin @('WinNT', 'ServerNT') -or
      [long]$record.Build -lt 22000 -or $record.BeforeServiceStatus -cnotin @('NotFound', 'Captured') -or
      $record.AfterServiceStatus -cne 'Captured' -or $record.AfterService.Name -cne 'sshd' -or
      $record.AfterService.State -cne 'Stopped' -or $record.BeforeFirewallStatus -cnotin @('NotFound', 'Captured') -or
      $record.AfterFirewallStatus -cnotin @('NotFound', 'Captured') -or $record.BeforeServerData.Status -cnotin @('NotFound', 'Captured') -or
      $record.AfterServerData.Status -cnotin @('NotFound', 'Captured')) {
    throw 'Saved OpenSSH Server installation state does not match the supported identity and schema.'
  }
  if ($record.BeforeFirewallStatus -ceq 'Captured') { Assert-RideOpenSshServerInstallFirewallIdentity $record.BeforeFirewall }
  if ($record.AfterFirewallStatus -ceq 'Captured') { Assert-RideOpenSshServerInstallFirewallIdentity $record.AfterFirewall }
  $record
}

function Get-RideOpenSshServerActiveInstallRunId {
  <#
  .SYNOPSIS
    Find the unique reversible RIDE install that owns the present capability.
  .DESCRIPTION
    Reads completed protected install snapshots for the exact local target. It
    refuses missing, non-removable, already-removed, or ambiguous ownership.
  .PARAMETER ExpectedComputerName
    Local target name expected by the operator.
  .PARAMETER ExpectedBuild
    Exact Windows build expected by the operator.
  .PARAMETER ExpectedEditionId
    Exact Windows EditionID expected by the operator.
  .OUTPUTS
    System.String. The single matching RIDE install RunId.
  .NOTES
    Read-only. This does not establish native acceptance or start sshd.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId
  )
  $root = Get-RideOpenSshServerInstallStateDirectory
  if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'No RIDE-owned OpenSSH Server installation snapshot exists; refusing capability removal.' }
  $matchingRunIds = New-Object System.Collections.Generic.List[string]
  foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter '*-completed.json' -File -Force)) {
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.Length -gt 65536) { throw 'OpenSSH Server installation snapshot path or size is invalid.' }
    $runId = $file.BaseName -replace '-completed$', ''
    if ($runId -notmatch '^[0-9a-fA-F]{32}$') { throw 'OpenSSH Server installation snapshot has an invalid RunId filename.' }
    if (Test-Path -LiteralPath (Join-Path $root ($runId + '-removed.json')) -PathType Leaf) { continue }
    $record = Read-RideOpenSshServerInstallSnapshot -RunId $runId
    if (-not $record.RemovalSupported -or $record.ComputerName -ine $ExpectedComputerName -or
        $record.Build -cne $ExpectedBuild -or $record.EditionId -ine $ExpectedEditionId) { continue }
    $matchingRunIds.Add($runId)
  }
  if ($matchingRunIds.Count -eq 0) { throw 'No reversible RIDE-owned OpenSSH Server installation matches this target; refusing capability removal.' }
  if ($matchingRunIds.Count -ne 1) { throw 'Multiple reversible RIDE-owned OpenSSH Server installations match this target; inspect saved runs before removal.' }
  $matchingRunIds[0]
}

function Install-RideOpenSshServerCapability {
  <#
  .SYNOPSIS
    Install OpenSSH Server without starting sshd or enabling new inbound access.
  .DESCRIPTION
    Captures the pre-install server surfaces, installs only the capability, then
    reconciles an exact TCP/22 rule to disabled when it was absent or disabled before
    servicing. A rule already enabled before installation is left unchanged.
  .PARAMETER ExpectedComputerName
    Local target name expected by the operator.
  .PARAMETER ExpectedBuild
    Exact Windows build expected by the operator.
  .PARAMETER ExpectedEditionId
    Exact Windows EditionID expected by the operator.
  .PARAMETER Source
    Optional servicing source directory.
  .PARAMETER LimitAccess
    Prevent Windows Update fallback for capability payload content.
  .PARAMETER RunId
    Optional caller-owned 32-character run ID so a future engine adapter can join
    the guarded component snapshot to its saved run without a second identifier.
  .EXAMPLE
    Install-RideOpenSshServerCapability -ExpectedComputerName $env:COMPUTERNAME -ExpectedBuild 26100 -ExpectedEditionId Professional -WhatIf
  .NOTES
    Source candidate only; it is not registered or declared supported pending native acceptance.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
    [string]$RunId,
    [ValidateNotNullOrEmpty()][string]$Source,
    [switch]$LimitAccess
  )
  if (-not (Test-RideOpenSshServerInstallAdministrator)) { throw 'OpenSSH Server installation requires an already elevated administrator session.' }
  if (Test-RideOpenSshServerInstallPendingReboot) { throw 'A servicing restart is pending; defer OpenSSH Server capability installation.' }
  $before = Get-RideOpenSshServerInstallFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
  if ($before.Capability.State -ceq 'Installed') {
    return [pscustomobject]@{ Status = 'AlreadyPresent'; CapabilityState = 'Installed'; ServiceStarted = $false; FirewallChanged = $false; RunId = $null; PostStateVerified = $true }
  }
  if ($before.ServiceStatus -ceq 'Captured' -and $before.Service.State -ceq 'Running') { throw 'An existing sshd service is running while its capability is reported absent; refusing to adopt this target.' }
  $beforeFirewallEnabled = if ($before.FirewallStatus -ceq 'Captured') { [string]$before.Firewall.Enabled } else { 'NotFound' }
  $intent = if ($beforeFirewallEnabled -eq 'True') { 'Install capability; preserve the existing enabled firewall state; never start sshd' } else { 'Install capability; leave TCP/22 blocked; never start sshd' }
  if (-not $PSCmdlet.ShouldProcess("$ExpectedComputerName / OpenSSH Server", $intent)) {
    return [pscustomobject]@{ Status = 'WhatIf'; CapabilityState = 'NotPresent'; ServiceStarted = $false; FirewallChanged = $false; RunId = $null; PostStateVerified = $false }
  }
  $record = [ordered]@{
    SchemaVersion = 1; Kind = 'OpenSshServerInstallState'; CapabilityName = 'OpenSSH.Server~~~~0.0.1.0'
    ComputerName = [string]$before.Context.ComputerName; Build = [string]$before.Context.Build; EditionId = [string]$before.Context.EditionId
    UpdateBuildRevision = [long]$before.Context.UpdateBuildRevision; ProductType = [string]$before.Context.ProductType
    BeforeServiceStatus = $before.ServiceStatus; BeforeService = $before.Service
    BeforeFirewallStatus = $before.FirewallStatus; BeforeFirewall = $before.Firewall
    BeforeCapabilityState = [string]$before.Capability.State
    BeforeServerData = $before.ServerData; Source = $Source; LimitAccess = [bool]$LimitAccess
    CreatedAtUtc = [DateTime]::UtcNow.ToString('o'); InstallStatus = 'Prepared'; RemovalSupported = $false
  }
  $saved = Save-RideOpenSshServerInstallSnapshot -Record $record -RunId $RunId
  $parameters = @{ Online = $true; Name = 'OpenSSH.Server~~~~0.0.1.0'; ErrorAction = 'Stop' }
  if ($Source) { $parameters.Source = $Source }
  if ($LimitAccess) { $parameters.LimitAccess = $true }
  try {
    Add-WindowsCapability @parameters | Out-Null
    $after = Get-RideOpenSshServerInstallFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
    if ($after.Capability.State -cne 'Installed') { throw 'OpenSSH Server capability did not reach Installed state.' }
    if ($after.ServiceStatus -cne 'Captured' -or $after.Service.Name -cne 'sshd' -or $after.Service.State -cne 'Stopped') { throw 'OpenSSH Server installation did not leave the exact sshd service present and stopped.' }
    if ($before.ServiceStatus -ceq 'Captured' -and ($after.Service.StartMode -cne $before.Service.StartMode -or $after.Service.StartName -cne $before.Service.StartName)) { throw 'OpenSSH Server installation changed the pre-existing sshd startup mode or account.' }
    if (-not (Test-RideOpenSshServerInstallDataEqual -Before $before.ServerData -After $after.ServerData)) { throw 'OpenSSH Server installation changed server configuration or host-key data; inspect the saved before/after observations.' }
    $firewallChanged = $false
    if ($beforeFirewallEnabled -ne 'True' -and $after.FirewallStatus -ceq 'Captured' -and $after.Firewall.Enabled -ceq 'True') {
      Assert-RideOpenSshServerInstallFirewallIdentity $after.Firewall
      Set-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -Enabled 'False' -ErrorAction Stop
      $firewallChanged = $true
      $after = Get-RideOpenSshServerInstallFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
    }
    if ($before.FirewallStatus -ceq 'Captured' -and $after.FirewallStatus -cne 'Captured') { throw 'OpenSSH Server installation removed a pre-existing firewall rule.' }
    if ($beforeFirewallEnabled -eq 'True' -and ($after.FirewallStatus -cne 'Captured' -or $after.Firewall.Enabled -cne 'True')) { throw 'OpenSSH Server installation changed the pre-existing enabled firewall rule.' }
    if ($beforeFirewallEnabled -ne 'True' -and $after.FirewallStatus -ceq 'Captured' -and $after.Firewall.Enabled -cne 'False') { throw 'OpenSSH Server installation left its inbound firewall rule enabled.' }
    if ($beforeFirewallEnabled -eq 'NotFound' -and $after.FirewallStatus -ceq 'Captured' -and $after.Firewall.Enabled -ne 'False') { throw 'OpenSSH Server installation created a firewall rule that is not disabled.' }
    $record.InstallStatus = 'Completed'
    $record.AfterCapabilityState = [string]$after.Capability.State
    $record.AfterServiceStatus = $after.ServiceStatus
    $record.AfterService = $after.Service
    $record.AfterFirewallStatus = $after.FirewallStatus
    $record.AfterFirewall = $after.Firewall
    $record.AfterServerData = $after.ServerData
    $record.CompletedAtUtc = [DateTime]::UtcNow.ToString('o')
    $record.RemovalSupported = ($before.ServiceStatus -ceq 'NotFound' -and $before.FirewallStatus -ceq 'NotFound' -and $before.ServerData.Status -ceq 'NotFound')
    $completed = Save-RideOpenSshServerInstallSnapshot -Record $record -RunId $saved.RunId
    [pscustomobject]@{ Status = 'Installed'; CapabilityState = [string]$after.Capability.State; ServiceStarted = $false; FirewallChanged = $firewallChanged; PriorFirewallState = $beforeFirewallEnabled; RunId = $saved.RunId; SnapshotPath = $completed.Path; PostStateVerified = $true; RemovalSupported = [bool]$record.RemovalSupported }
  } catch {
    throw "OpenSSH Server capability installation may be partial; pre-install state is saved as '$($saved.RunId)'. Inspect all server surfaces before retrying. $($_.Exception.Message)"
  }
}

function Remove-RideOpenSshServerCapability {
  <#
  .SYNOPSIS
    Remove an OpenSSH Server capability installed by a matching saved RIDE run.
  .DESCRIPTION
    Restores NotPresent only when service, firewall and server data still match the
    saved install. Removal is limited to runs that began without those server surfaces.
  .PARAMETER RunId
    Saved installation run ID returned by Install-RideOpenSshServerCapability.
  .PARAMETER ExpectedComputerName
    Local target name expected by the operator.
  .PARAMETER ExpectedBuild
    Exact Windows build expected by the operator.
  .PARAMETER ExpectedEditionId
    Exact Windows EditionID expected by the operator.
  .EXAMPLE
    Remove-RideOpenSshServerCapability -RunId $runId -ExpectedComputerName $env:COMPUTERNAME -ExpectedBuild 26100 -ExpectedEditionId Professional -WhatIf
  .NOTES
    Candidate remains unregistered pending disposable Windows acceptance.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId
  )
  if (-not (Test-RideOpenSshServerInstallAdministrator)) { throw 'OpenSSH Server removal requires an already elevated administrator session.' }
  if (Test-RideOpenSshServerInstallPendingReboot) { throw 'A servicing restart is pending; defer OpenSSH Server capability removal.' }
  $record = Read-RideOpenSshServerInstallSnapshot $RunId
  if ($record.ComputerName -ine $ExpectedComputerName -or $record.Build -cne $ExpectedBuild -or $record.EditionId -ine $ExpectedEditionId) { throw 'Saved OpenSSH Server installation belongs to another target.' }
  if (-not $record.RemovalSupported) { throw 'This installation changed a pre-existing server surface; automatic capability removal is unsupported for this saved run.' }
  $fresh = Get-RideOpenSshServerInstallFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
  $root = Get-RideOpenSshServerInstallStateDirectory
  $removedPath = Join-Path $root ($RunId + '-removed.json')
  if ($fresh.Capability.State -ceq 'NotPresent') {
    if (Test-Path -LiteralPath $removedPath -PathType Leaf) { return [pscustomobject]@{ Status = 'AlreadyRemoved'; CapabilityState = 'NotPresent'; RunId = $RunId; PostStateVerified = $true } }
    if ($record.InstallStatus -cne 'Completed' -or -not $record.RemovalSupported) { throw 'OpenSSH Server capability is absent but this run has no completed removable installation record; refusing to infer ownership.' }
    if ($fresh.ServiceStatus -cne 'NotFound') { throw 'OpenSSH Server capability is absent but an sshd service remains; inspect the partial removal before retrying.' }
    if (-not (Test-RideOpenSshServerInstallDataEqual -Before $record.BeforeServerData -After $fresh.ServerData)) { throw 'OpenSSH Server capability is absent but server data differs from the captured pre-install state; refusing partial-removal recovery.' }
    if ($fresh.FirewallStatus -ceq 'Captured') {
      Assert-RideOpenSshServerInstallFirewallIdentity $fresh.Firewall
      if ($record.AfterFirewallStatus -cne 'Captured' -or $record.AfterFirewall.Enabled -cne 'False' -or
          $fresh.Firewall.Enabled -cne 'False' -or $fresh.Firewall.Direction -cne $record.AfterFirewall.Direction -or
          $fresh.Firewall.Action -cne $record.AfterFirewall.Action -or $fresh.Firewall.Profile -cne $record.AfterFirewall.Profile -or
          $fresh.Firewall.Protocol -cne $record.AfterFirewall.Protocol -or $fresh.Firewall.LocalPort -cne $record.AfterFirewall.LocalPort) {
        throw 'OpenSSH Server capability is absent but the remaining firewall rule differs from the saved disabled rule; refusing partial-removal recovery.'
      }
    } elseif ($fresh.FirewallStatus -cne 'NotFound') {
      throw 'OpenSSH Server capability is absent and firewall state is ambiguous; refusing partial-removal recovery.'
    }
    if (-not $PSCmdlet.ShouldProcess("$ExpectedComputerName / OpenSSH Server / $RunId", 'Finish this saved partial removal and verify the captured absent state')) {
      return [pscustomobject]@{ Status = 'WhatIf'; CapabilityState = 'NotPresent'; RunId = $RunId; PostStateVerified = $false }
    }
    try {
      if ($fresh.FirewallStatus -ceq 'Captured') {
        Remove-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop
      }
      $after = Get-RideOpenSshServerInstallFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
      if ($after.Capability.State -cne 'NotPresent' -or $after.ServiceStatus -cne 'NotFound' -or $after.FirewallStatus -cne 'NotFound' -or
          -not (Test-RideOpenSshServerInstallDataEqual -Before $record.BeforeServerData -After $after.ServerData)) {
        throw 'OpenSSH Server surfaces did not return to their captured absent state.'
      }
      $null = Save-RideOpenSshServerRemovalMarker -RunId $RunId -ComputerName $record.ComputerName
      return [pscustomobject]@{ Status = 'RecoveredPartialRemoval'; CapabilityState = 'NotPresent'; RunId = $RunId; PostStateVerified = $true; RecoverySupported = $true }
    } catch {
      throw "OpenSSH Server partial-removal recovery failed; inspect the remaining firewall/server surfaces and retain saved run '$RunId'. $($_.Exception.Message)"
    }
  }
  if ($fresh.Capability.State -cne 'Installed') { throw 'Current OpenSSH Server capability state is not Installed; refusing removal.' }
  if ($fresh.ServiceStatus -cne $record.AfterServiceStatus -or $fresh.Service.State -cne $record.AfterService.State -or
      $fresh.Service.StartMode -cne $record.AfterService.StartMode -or $fresh.Service.StartName -cne $record.AfterService.StartName) {
    throw 'OpenSSH Server service state drifted from the saved installation; refusing removal.'
  }
  if ($fresh.Service.State -ceq 'Running') { throw 'OpenSSH Server is running; stop and separately review activation before capability removal.' }
  if ($fresh.FirewallStatus -cne $record.AfterFirewallStatus) { throw 'OpenSSH Server firewall state drifted from the saved installation; refusing removal.' }
  if ($fresh.FirewallStatus -ceq 'Captured') {
    Assert-RideOpenSshServerInstallFirewallIdentity $fresh.Firewall
    if ($fresh.Firewall.Enabled -cne $record.AfterFirewall.Enabled -or $fresh.Firewall.Direction -cne $record.AfterFirewall.Direction -or
        $fresh.Firewall.Action -cne $record.AfterFirewall.Action -or $fresh.Firewall.Profile -cne $record.AfterFirewall.Profile -or
        $fresh.Firewall.Protocol -cne $record.AfterFirewall.Protocol -or $fresh.Firewall.LocalPort -cne $record.AfterFirewall.LocalPort) {
      throw 'OpenSSH Server firewall rule drifted from the saved installation; refusing removal.'
    }
  }
  if (-not (Test-RideOpenSshServerInstallDataEqual -Before $record.AfterServerData -After $fresh.ServerData)) { throw 'OpenSSH Server configuration or host-key data drifted since installation; refusing removal.' }
  if (-not $PSCmdlet.ShouldProcess("$ExpectedComputerName / OpenSSH Server / $RunId", 'Remove the capability and restore its captured NotPresent state')) {
    return [pscustomobject]@{ Status = 'WhatIf'; CapabilityState = 'Installed'; RunId = $RunId; PostStateVerified = $false }
  }
  try {
    Remove-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction Stop | Out-Null
    $after = Get-RideOpenSshServerInstallFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
    if ($after.Capability.State -cne 'NotPresent') { throw 'OpenSSH Server capability did not return to NotPresent.' }
    if ($after.ServiceStatus -cne 'NotFound') { throw 'OpenSSH Server service remains after capability removal.' }
    if ($after.FirewallStatus -ceq 'Captured') {
      Assert-RideOpenSshServerInstallFirewallIdentity $after.Firewall
      if ($after.Firewall.Enabled -cne 'False' -or $after.Firewall.Direction -cne $record.AfterFirewall.Direction -or
          $after.Firewall.Action -cne $record.AfterFirewall.Action -or $after.Firewall.Profile -cne $record.AfterFirewall.Profile -or
          $after.Firewall.Protocol -cne $record.AfterFirewall.Protocol -or $after.Firewall.LocalPort -cne $record.AfterFirewall.LocalPort) {
        throw 'OpenSSH Server removal left a changed or enabled firewall rule; refusing to remove it.'
      }
      Remove-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop
      $after = Get-RideOpenSshServerInstallFreshState $ExpectedComputerName $ExpectedBuild $ExpectedEditionId
    }
    if ($after.FirewallStatus -cne 'NotFound') { throw 'OpenSSH Server removal did not remove its newly created firewall rule.' }
    if (-not (Test-RideOpenSshServerInstallDataEqual -Before $record.BeforeServerData -After $after.ServerData)) { throw 'OpenSSH Server removal changed pre-install configuration or host-key data.' }
    $null = Save-RideOpenSshServerRemovalMarker -RunId $RunId -ComputerName $record.ComputerName
    [pscustomobject]@{ Status = 'Removed'; CapabilityState = [string]$after.Capability.State; RunId = $RunId; PostStateVerified = $true; RecoverySupported = $true }
  } catch {
    throw "OpenSSH Server capability removal may be partial; inspect all server surfaces and retain saved run '$RunId'. $($_.Exception.Message)"
  }
}

Export-ModuleMember -Function Install-RideOpenSshServerCapability,Remove-RideOpenSshServerCapability,Get-RideOpenSshServerActiveInstallRunId
