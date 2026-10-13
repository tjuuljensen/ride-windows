<#
.SYNOPSIS
  Inspect and recover local Windows Firewall profile enablement.
.DESCRIPTION
  Reads declared Domain/Private/Public profiles in PersistentStore and ActiveStore,
  plus active network categories and legacy policy-key presence. Writes only local
  Enabled fields. Captures all declared profiles before mutation and reports partial
  completion. Imports define commands only; no firewall state is read or changed.
.EXAMPLE
  Import-Module ./modules/RIDE-FirewallProfiles.psm1
  Get-Help Get-RideFirewallProfileState -Full
.INPUTS
  None. Parameters are explicit.
.OUTPUTS
  Inspection returns objects; mutations return no data.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: NetSecurity/NetConnection; administrator rights for machine writes.
  Inputs: Exact catalog profile names; snapshot version 1 local Enabled values.
  Recovery: Engine-owned ShouldProcess and saved-run capture. Direct setters are
  internal and bypass engine preview/target/elevation gates. No rule/service reset.
  Author: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add local/effective profile inspection and bounded local recovery.
  Supported targets remain empty until disposable VM acceptance, currently held
  for manual user confirmation. Local mocked checks do not establish support.
.LINK
  ../docs/firewall-profiles.md
.LINK
  https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile
#>

$script:ModuleVersion = '0.1.0'
$ErrorActionPreference = 'Stop'

function Assert-RideFirewallProfiles {
  param([hashtable] $Operation)
  $names = @($Operation.FirewallProfiles)
  if ($Operation.Kind -ne 'FirewallProfile' -or $names.Count -notin @(1, 3) -or
      @($names | Where-Object { $_ -notin @('Domain', 'Private', 'Public') }).Count -or
      @($names | Sort-Object -Unique).Count -ne $names.Count) {
    throw 'Firewall profiles must be exact, unique Domain/Private/Public identities.'
  }
}

function Get-RideFirewallProfileRows {
  param([string[]] $Names, [string] $Store)
  $rows = @(Get-NetFirewallProfile -Name $Names -PolicyStore $Store -ErrorAction Stop)
  foreach ($name in $Names) {
    if (@($rows | Where-Object Name -eq $name).Count -ne 1) {
      throw "Firewall profile '$name' is missing or duplicated in $Store."
    }
  }
  if ($rows.Count -ne $Names.Count) { throw "Unexpected firewall profile identity returned by $Store." }
  $rows
}

function Get-RideFirewallProfileState {
  <#
  .SYNOPSIS
    Inspect declared local and effective Enabled values without writes.
  .PARAMETER Operation
    Fixed profile identities from catalog metadata.
  .OUTPUTS
    Object with Entries (local Value, EffectiveValue, conflict and source), active
    network profiles, legacy-key presence and local recovery readiness.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation)
  Assert-RideFirewallProfiles $Operation
  $names = @($Operation.FirewallProfiles)
  $local = @(Get-RideFirewallProfileRows $names PersistentStore)
  $effective = @(Get-RideFirewallProfileRows $names ActiveStore)
  $networks = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; InterfaceIndex = $_.InterfaceIndex; Profile = switch ([string]$_.NetworkCategory) {
      DomainAuthenticated { 'Domain' }; Private { 'Private' }; Public { 'Public' }; default { 'Unknown' }
    } }
  })
  $entries = @(foreach ($name in $names) {
    $configured = @($local | Where-Object Name -eq $name)[0]
    $active = @($effective | Where-Object Name -eq $name)[0]
    $value = [string]$configured.Enabled
    $effectiveValue = [string]$active.Enabled
    if ($value -notin @('True', 'False', 'NotConfigured') -or $effectiveValue -notin @('True', 'False', 'NotConfigured')) {
      throw "Unknown firewall Enabled representation for '$name'."
    }
    [pscustomobject]@{
      Name = $name; Value = $value; EffectiveValue = $effectiveValue
      PolicyConflict = ($value -ne $effectiveValue)
      EffectiveSource = $(if ($active.PolicyStoreSource) { [string]$active.PolicyStoreSource } else { 'ActiveStore; source not exposed' })
      Active = ($name -in $networks.Profile)
    }
  })
  [pscustomobject]@{
    SnapshotVersion = 1; Available = $true; PolicyStore = 'PersistentStore'; Entries = $entries
    CanRestoreLocal = (@($entries | Where-Object Value -eq 'NotConfigured').Count -eq 0)
    ActiveNetworks = $networks
    LegacyStandardProfileKeyPresent = [bool](Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile' -ErrorAction Stop)
  }
}

function Set-RideFirewallProfileEntries {
  param([hashtable] $Operation, [object[]] $Entries, $ExpectedState)
  Assert-RideFirewallProfiles $Operation
  $names = @($Operation.FirewallProfiles)
  if ($Entries.Count -ne $names.Count -or @($Entries.Name | Sort-Object -Unique).Count -ne $names.Count -or
      @($Entries | Where-Object { $_.Name -notin $names -or $_.Value -isnot [string] -or $_.Value -notin @('True', 'False') }).Count) {
    throw 'Invalid firewall profile snapshot identities or local Enabled values; local NotConfigured cannot be restored.'
  }
  $before = Get-RideFirewallProfileState $Operation
  if (-not $before.CanRestoreLocal) { throw 'Local firewall NotConfigured is not recoverable through the local setter; no profile was changed.' }
  if ($ExpectedState) {
    if ($ExpectedState.Entries.Count -ne $names.Count -or
        @($ExpectedState.Entries.Name | Sort-Object -Unique).Count -ne $names.Count) { throw 'Incomplete firewall pre-change capture.' }
    foreach ($entry in $before.Entries) {
      $expected = @($ExpectedState.Entries | Where-Object Name -eq $entry.Name)
      if ($expected.Count -ne 1 -or $entry.Value -ne $expected[0].Value) { throw "Firewall profile '$($entry.Name)' changed after capture; no profile was changed." }
    }
  }
  $completed = New-Object 'System.Collections.Generic.List[string]'
  foreach ($name in $names) {
    $entry = @($Entries | Where-Object Name -eq $name)[0]
    $original = @($before.Entries | Where-Object Name -eq $name)[0]
    try {
      # Recheck immediately before each write to avoid overwriting visible concurrent changes.
      $live = @(Get-RideFirewallProfileRows @($name) PersistentStore)[0]
      if ([string]$live.Enabled -ne $original.Value) { throw 'Local state changed during this batch.' }
      if ($original.Value -ne $entry.Value) {
        Set-NetFirewallProfile -Name $name -PolicyStore PersistentStore -Enabled $entry.Value -ErrorAction Stop | Out-Null
        $after = @(Get-RideFirewallProfileRows @($name) PersistentStore)[0]
        if ([string]$after.Enabled -ne $entry.Value) { throw 'Local Enabled readback did not match.' }
      }
      $completed.Add($name)
    }
    catch {
      throw "Firewall profile '$name' failed. Completed profiles: $($completed -join ', '). Remaining profiles may be unchanged or partially changed; use the saved run. $($_.Exception.Message)"
    }
  }
}

function Set-RideFirewallProfileState {
  <#
  .SYNOPSIS
    Set only local Enabled for declared profiles, with a complete preflight capture.
  .PARAMETER Operation
    Catalog profile metadata; engine owns target, elevation and preview checks.
  .PARAMETER State
    Declared On or explicit advanced Off. Enable-all offers On only.
  .PARAMETER ExpectedState
    Engine pre-change capture; configuration drift prevents writes.
  .OUTPUTS
    None. Failed profile and partial completion are reported by exceptions.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation, [Parameter(Mandatory)][string] $State, $ExpectedState)
  if (-not $Operation.States.ContainsKey($State) -or $Operation.States[$State] -isnot [string] -or $Operation.States[$State] -notin @('True', 'False')) { throw 'Unsupported firewall state.' }
  if (@($Operation.FirewallProfiles).Count -gt 1 -and $Operation.States[$State] -ne 'True') { throw 'Multi-profile firewall action supports enablement only.' }
  $entries = @($Operation.FirewallProfiles | ForEach-Object { [pscustomobject]@{ Name = $_; Value = $Operation.States[$State] } })
  Set-RideFirewallProfileEntries $Operation $entries $ExpectedState
}

function Restore-RideFirewallProfileState {
  <#
  .SYNOPSIS
    Restore captured local flags; effective managed values never become local writes.
  .PARAMETER Operation
    Exact catalog profile identities.
  .PARAMETER Snapshot
    Version 1, PersistentStore entries with original and requested Enabled values.
  .OUTPUTS
    None. Unknown/conflicting snapshots fail before any write; repeat recovery is safe.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation, [Parameter(Mandatory)] $Snapshot)
  Assert-RideFirewallProfiles $Operation
  if ($Snapshot.SnapshotVersion -ne 1 -or $Snapshot.PolicyStore -ne 'PersistentStore' -or
      @($Snapshot.Entries | Where-Object { $_.ExpectedValue -isnot [string] -or $_.ExpectedValue -notin @('True', 'False') }).Count) { throw 'Unsupported firewall snapshot version, store or expected local state.' }
  $current = Get-RideFirewallProfileState $Operation
  foreach ($entry in $Snapshot.Entries) {
    $live = @($current.Entries | Where-Object Name -eq $entry.Name)
    if ($live.Count -ne 1 -or $live[0].Value -notin @($entry.Value, $entry.ExpectedValue)) { throw 'Firewall recovery conflicts with current local state; no profile was changed.' }
  }
  Set-RideFirewallProfileEntries $Operation @($Snapshot.Entries) $current
}

Export-ModuleMember -Function Get-RideFirewallProfileState, Set-RideFirewallProfileState, Restore-RideFirewallProfileState
