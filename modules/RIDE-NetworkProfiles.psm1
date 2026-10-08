<#
.SYNOPSIS
  Capture, apply, and restore non-domain network profile categories.

.DESCRIPTION
  Captures interface index, name, and category; Set skips domain-authenticated profiles; Restore
  matches captured identities and reports missing/failed profiles as a combined failure. Import
  defines commands only.

.EXAMPLE
  Import-Module .\modules\RIDE-NetworkProfiles.psm1
  Import definitions; inspect exported commands with Get-Help before use.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return the types documented in their individual help.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: NetConnection cmdlets and machine-administrator context for changes.
  File/environment inputs: Catalog Private/Public state maps and saved profile identities.
  Recovery: State-changing handlers are engine-internal: use ride.ps1 preview and captured-run
  restoration. Direct calls bypass ShouldProcess and snapshot capture.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Initial focused network profile lifecycle handler (existing version retained).
  Supported targets are declared per operation in catalog/operations.psd1. This walkthrough
  validates syntax/help, not Windows state transitions.

.LINK
  docs/models/script-repository-model.md

.LINK
  docs/OPERATIONS.md

#>


$script:ModuleVersion = '0.1.0'

function Get-RideNetworkProfileState {
  <#
  .SYNOPSIS
    Capture identity and category of non-domain connection profiles.

  .DESCRIPTION
    Reads Get-NetConnectionProfile and excludes DomainAuthenticated profiles. Operation is retained
    as the handler contract even though this read does not use its fields.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideNetworkProfileState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Profiles with InterfaceIndex, Name, and
    NetworkCategory.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $profiles = @(Get-NetConnectionProfile -ErrorAction Stop | Where-Object { $_.NetworkCategory -ne 'DomainAuthenticated' })
  [pscustomobject]@{
    Profiles = @($profiles | ForEach-Object {
        [pscustomobject]@{
          InterfaceIndex = [uint32]$_.InterfaceIndex
          Name = [string]$_.Name
          NetworkCategory = [string]$_.NetworkCategory
        }
      })
  }
}

function Set-RideNetworkProfileState {
  <#
  .SYNOPSIS
    Apply a declared category to all reported non-domain profiles.

  .DESCRIPTION
    Validates the catalog state, skips already matching profiles, and fails when no eligible
    profiles exist. Reports the specific failed profile; earlier updates may already have completed.
    Invoke through the engine.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER State
    Declared desired state for the selected catalog operation.

  .EXAMPLE
    Get-Help Set-RideNetworkProfileState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $State
  )

  if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'" }
  $category = [string]$Operation.States[$State]
  $current = Get-RideNetworkProfileState -Operation $Operation
  if ($current.Profiles.Count -eq 0) { throw 'No reported non-domain connection profiles are available to change.' }

  foreach ($profile in $current.Profiles) {
    if ($profile.NetworkCategory -eq $category) { continue }
    try {
      Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory $category -ErrorAction Stop | Out-Null
    }
    catch {
      throw "Could not set network profile '$($profile.Name)' (interface $($profile.InterfaceIndex)) to '$category': $($_.Exception.Message)"
    }
  }
}

function Restore-RideNetworkProfileState {
  <#
  .SYNOPSIS
    Restore categories using each captured profile identity.

  .DESCRIPTION
    Matches InterfaceIndex and Name, skips already matching categories, and combines
    missing-profile/update failures after attempting the captured list. Use Restore-RideRun.

  .PARAMETER Snapshot
    Captured pre-change state for this operation, read from the matching saved run.

  .EXAMPLE
    Get-Help Restore-RideNetworkProfileState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)] $Snapshot)

  $savedProfiles = @($Snapshot.Profiles)
  if ($savedProfiles.Count -eq 0) { return }
  $currentProfiles = @(Get-NetConnectionProfile -ErrorAction Stop)
  $failures = New-Object System.Collections.Generic.List[string]

  foreach ($saved in $savedProfiles) {
    $profile = $currentProfiles | Where-Object { [uint32]$_.InterfaceIndex -eq [uint32]$saved.InterfaceIndex -and [string]$_.Name -eq [string]$saved.Name } | Select-Object -First 1
    if (-not $profile) {
      $failures.Add("Network profile '$($saved.Name)' on interface $($saved.InterfaceIndex) is no longer available.")
      continue
    }
    if ($profile.NetworkCategory -eq $saved.NetworkCategory) { continue }
    try {
      Set-NetConnectionProfile -InterfaceIndex ([uint32]$saved.InterfaceIndex) -NetworkCategory ([string]$saved.NetworkCategory) -ErrorAction Stop | Out-Null
    }
    catch {
      $failures.Add("Could not restore network profile '$($saved.Name)' on interface $($saved.InterfaceIndex): $($_.Exception.Message)")
    }
  }

  if ($failures.Count -gt 0) { throw ($failures -join ' ') }
}

Export-ModuleMember -Function Get-RideNetworkProfileState, Set-RideNetworkProfileState, Restore-RideNetworkProfileState
