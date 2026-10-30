<#
.SYNOPSIS
  Capture and restore NetBIOS interface preferences and bounded local firewall flags.
.DESCRIPTION
  Uses existing NetBT interface GUIDs, existing Remote Desktop rules and the exact
  OpenSSH-Server-In-TCP rule. OpenSSH exposure requires its installed capability and
  verified local inbound TCP/22 identity. NetBIOS uses the legacy registry preference,
  preserving raw types and absence; the CIM DHCP-mode setter cannot recover every
  static-IP adapter configuration. Does not create rules, install services, alter GPO
  or change authentication.
  The engine owns preview, elevation and complete pre-change snapshots.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Registry/NetSecurity; machine administrator rights for writes.
  Recovery: Captured adapter options/rule flags; missing or changed identities fail before writes.
  Owner: RIDE-Windows maintainers. Version: 0.2.0.
  Changelog: 0.2.0: Add capability-bound exact OpenSSH TCP/22 rule recovery.
    0.1.0: Add GUID-bound NetBIOS and local Remote Desktop firewall recovery.
#>
Import-Module (Join-Path $PSScriptRoot 'RIDE-Settings.psm1') -Force
function Get-RideNetbiosInterfaceIds {
  <#
  .SYNOPSIS
    Enumerate existing GUID-named NetBT interface preference keys without creating them.
  .OUTPUTS
    Canonical GUID strings; unknown key names are excluded.
  #>
  $root='HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
  if (-not (Test-Path -LiteralPath $root -ErrorAction Stop)) { return }
  Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
    if ($_.PSChildName -match '^Tcpip_(\{[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\})$') {
      ([guid]$Matches[1]).ToString()
    }
  } | Sort-Object -Unique
}
function Get-RideNetbiosRegistryOperation {
  <#
  .SYNOPSIS
    Build a fixed-root registry target from a validated interface GUID.
  .PARAMETER Id
    Interface GUID; no snapshot path is accepted.
  .OUTPUTS
    Focused registry operation metadata.
  #>
  param([guid] $Id)
  @{RegistryPath=('HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_'+$Id.ToString('B'));ValueName='NetbiosOptions';ValueType='DWord'}
}
function Assert-RideOpenSshFirewallRuleIdentity {
  <#
  .SYNOPSIS
    Confirm that the named local rule is exactly the OpenSSH inbound TCP/22 rule.
  .PARAMETER Rule
    One rule returned from PersistentStore.
  .OUTPUTS
    None. Throws before mutation if the rule differs from its declared identity.
  #>
  param([Parameter(Mandatory)]$Rule)
  if ($Rule.Name -cne 'OpenSSH-Server-In-TCP' -or $Rule.Direction -cne 'Inbound' -or
      $Rule.Action -cne 'Allow' -or $Rule.Profile -cnotin @('Any', 'Domain, Private, Public') -or
      $Rule.PolicyStoreSourceType -cne 'Local' -or $Rule.PolicyStoreSource -cnotin @('PersistentStore', 'Local') -or
      [string]$Rule.Enabled -cnotin @('True', 'False', 'NotConfigured')) {
    throw 'OpenSSH firewall rule differs from the exact local inbound rule identity; refusing to change it.'
  }
  $ports = @(Get-RideOpenSshFirewallPortFilter -Rule $Rule)
  if ($ports.Count -ne 1 -or [string]$ports[0].Protocol -notin @('TCP', '6') -or
      [string]$ports[0].LocalPort -cne '22') {
    throw 'OpenSSH firewall rule is not limited to inbound TCP port 22; refusing to change it.'
  }
}
function Get-RideOpenSshFirewallPortFilter {
  <#
  .SYNOPSIS
    Read the port filter associated with one already inspected OpenSSH rule.
  .PARAMETER Rule
    The native firewall rule object returned by NetSecurity.
  .OUTPUTS
    Port filter objects associated with that rule.
  #>
  param([Parameter(Mandatory)]$Rule)
  Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
}
function Get-RideNetworkControlState {
  <#
  .SYNOPSIS
    Inspect the fixed NetBIOS, Remote Desktop or OpenSSH firewall target.
  .PARAMETER Operation
    NetBios or RemoteDesktopFirewall catalog metadata.
  .OUTPUTS
    Availability and exact target/value entries.
  #>
  param([hashtable] $Operation)
  switch ($Operation.Kind) {
    NetBios {
      $entries = @(Get-RideNetbiosInterfaceIds | ForEach-Object {
        $target=Get-RideNetbiosRegistryOperation -Id $_
        $null=Get-Item -LiteralPath $target.RegistryPath -ErrorAction Stop
        $state=Get-RideSettingState -Operation $target
        [pscustomobject]@{Id=$_;Value=$state.Value;Exists=$state.Exists;ValueType=$state.ValueType;KeyExisted=$true}
      })
    }
    RemoteDesktopFirewall {
      if ($Operation.FirewallRuleNames) {
        if (@($Operation.FirewallRuleNames).Count -ne 1 -or $Operation.FirewallRuleNames[0] -cne 'OpenSSH-Server-In-TCP' -or
            $Operation.RequiredCapabilityName -cne 'OpenSSH.Server~~~~0.0.1.0') {
          throw 'Unsupported exact firewall-rule target.'
        }
        $capability = @(Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction Stop)
        if ($capability.Count -ne 1) { throw 'OpenSSH Server capability state is unavailable or ambiguous.' }
        if ($capability[0].State -cne 'Installed') {
          return [pscustomobject]@{ Available = $false; Reason = 'The OpenSSH Server capability is not installed.'; Entries = @() }
        }
        try { $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop) }
        catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }; $rules=@() }
        if ($rules.Count -gt 1) { throw 'OpenSSH local firewall rule identity is ambiguous.' }
        foreach ($rule in $rules) { Assert-RideOpenSshFirewallRuleIdentity -Rule $rule }
      } else {
        try { $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'RemoteDesktop-*' -ErrorAction Stop) }
        catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }; $rules=@() }
      }
      $entries = @($rules | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Id=$_.Name; Value=$_.Enabled.ToString() } })
    }
    default { throw 'Unsupported network control.' }
  }
  if ($Operation.Kind -eq 'NetBios') { return [pscustomobject]@{SnapshotVersion=2;Available=($entries.Count -gt 0);Entries=$entries} }
  [pscustomobject]@{ Available=($entries.Count -gt 0); Entries=$entries }
}
function Set-RideNetworkControlEntries {
  <#
  .SYNOPSIS
    Validate all captured identities and values before changing network controls.
  .PARAMETER Operation
    Fixed catalog kind; snapshots cannot choose another target family.
  .PARAMETER Entries
    Existing interface GUIDs with typed registry snapshots or local rule names with flags.
  .OUTPUTS
    None. Validate every identity and type before writes; errors propagate.
  #>
  param([hashtable] $Operation, [object[]] $Entries, [switch] $Restore)
  if (-not $Entries.Count) { throw 'No available network controls.' }
  if (@($Entries.Id | Select-Object -Unique).Count -ne $Entries.Count) { throw 'Duplicate network-control snapshot identities.' }
  $current=Get-RideNetworkControlState $Operation
  $writes=foreach ($entry in $Entries) {
    if (@($current.Entries | Where-Object Id -eq $entry.Id).Count -ne 1) { throw 'Captured network control is missing.' }
    if ($Operation.Kind -eq 'NetBios') {
      $target=Get-RideNetbiosRegistryOperation -Id ([guid]$entry.Id)
      if ($entry.Exists -isnot [bool] -or $entry.KeyExisted -ne $true -or ($entry.Exists -and $entry.ValueType -notin @('String','ExpandString','DWord','QWord','Binary','MultiString'))) { throw 'Invalid NetBIOS registry snapshot.' }
      if (-not $Restore -and ($entry.Value -isnot [int] -or $entry.Value -notin @(0,1,2) -or $entry.ValueType -ne 'DWord' -or -not $entry.Exists)) { throw 'Invalid NetBIOS preference.' }
      [pscustomobject]@{Target=$target;Snapshot=$entry;Before=@($current.Entries | Where-Object Id -eq $entry.Id)[0]}
    }
    elseif ($Operation.Kind -eq 'RemoteDesktopFirewall') {
      $validId = if ($Operation.FirewallRuleNames) { $entry.Id -cin $Operation.FirewallRuleNames } else { $entry.Id -match '^RemoteDesktop-[^*?\r\n]+$' }
      if (-not $validId -or $entry.Value -notin @('True','False','NotConfigured')) { throw 'Invalid local firewall snapshot.' }
      [pscustomobject]@{ Id=$entry.Id; Value=$entry.Value; Before=@($current.Entries | Where-Object Id -eq $entry.Id)[0].Value }
    }
    else { throw 'Unsupported network control.' }
  }
  foreach ($write in $writes) {
    if ($Operation.Kind -eq 'NetBios') {
      if ($Restore) { Restore-RideSettingState -Operation $write.Target -Snapshot $write.Snapshot }
      elseif (-not $write.Before.Exists -or $write.Before.ValueType -ne 'DWord' -or $write.Before.Value -ne $write.Snapshot.Value) { Set-RideSettingState -Operation $write.Target -Value $write.Snapshot.Value }
    }
    elseif ($write.Before -ne $write.Value) { Set-NetFirewallRule -PolicyStore PersistentStore -Name $write.Id -Enabled $write.Value -ErrorAction Stop | Out-Null }
  }
}
function Set-RideNetworkControlState {
  <#
  .SYNOPSIS
    Apply one declared state to currently reported network controls.
  .PARAMETER Operation
    Catalog metadata.
  .PARAMETER State
    Declared state name; NetBIOS Dhcp means 0, not explicit enablement.
  .OUTPUTS
    None; unavailable controls or native failures throw.
  #>
  param([hashtable] $Operation,[string] $State)
  if (-not $Operation.States.ContainsKey($State)) { throw 'Invalid network control state.' }
  $entries=@((Get-RideNetworkControlState $Operation).Entries | ForEach-Object {
    if ($Operation.Kind -eq 'NetBios') { [pscustomobject]@{Id=$_.Id;Value=$Operation.States[$State];Exists=$true;KeyExisted=$true;ValueType='DWord'} }
    else { [pscustomobject]@{Id=$_.Id;Value=$Operation.States[$State]} }
  })
  Set-RideNetworkControlEntries $Operation $entries
}
function Restore-RideNetworkControlState {
  <#
  .SYNOPSIS
    Restore captured individual flags/options; new identities remain untouched.
  .PARAMETER Operation
    Fixed catalog metadata.
  .PARAMETER Snapshot
    Captured entries and availability.
  .OUTPUTS
    None; invalid/unavailable snapshots fail before writes.
  #>
  param([hashtable] $Operation,$Snapshot)
  if (-not $Snapshot.Available) { throw 'Unavailable network-control snapshot.' }
  if ($Operation.Kind -eq 'NetBios' -and $Snapshot.SnapshotVersion -ne 2) { throw 'The earlier CIM-only NetBIOS snapshot requires its disposable-VM checkpoint recovery; raw registry state was not captured.' }
  Set-RideNetworkControlEntries $Operation @($Snapshot.Entries) -Restore
}
Export-ModuleMember -Function Get-RideNetworkControlState, Set-RideNetworkControlState, Restore-RideNetworkControlState
