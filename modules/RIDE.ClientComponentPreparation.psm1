<#
.SYNOPSIS
  Prepare explicit OpenSSH Client or Telnet Client servicing from saved observations.
.DESCRIPTION
  Builds data-only command outlines for two separately chosen client components.
  Requires an explicit source mode, preserves provider identity, and blocks unknown
  or pending states. No DISM invocation, source acquisition, feature change or reboot.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  File/environment inputs: Supplied component inventory and explicit local-source path.
  Recovery: Version-1 preparation records original literal state; no exact payload,
  dependency or servicing recovery is claimed. No engine/catalog operation added.
  Version: 0.3.0.
  Changelog: 0.3.0: Rename Offline to LocalSource to avoid implying network isolation.
  0.2.0: Distinguish Windows Update blocking from configured source fallback.
  0.1.0: Add independently selected client preparation/source boundaries.
.LINK
  ../docs/windows-component-inventory.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.ComponentInventory.psm1') -ErrorAction Stop
$script:ClientPreparationNames=@(
  @{Kind='Capability';Name='OpenSSH.Client~~~~0.0.1.0';PresentState='Installed';AbsentStates=@('NotPresent');Add='Dism\Add-WindowsCapability';Remove='Dism\Remove-WindowsCapability'},
  @{Kind='OptionalFeature';Name='TelnetClient';PresentState='Enabled';AbsentStates=@('Disabled','DisabledWithPayloadRemoved');Add='Dism\Enable-WindowsOptionalFeature';Remove='Dism\Disable-WindowsOptionalFeature'}
)

function Get-RideClientComponentPreparationChoice {
  <#
  .SYNOPSIS
    List the two prioritized client identities using only supplied observations.
  .PARAMETER Inventory
    Schema-1 WindowsComponentObservation from the intended target.
  .EXAMPLE
    Get-RideClientComponentPreparationChoice -Inventory $savedComponents
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject collection. Exact provider/name, lookup status and literal state.
  .NOTES
    Neither choice is selected by default; a missing name is not guessed or discovered.
    These preparatory native identities are not new supported catalog operations.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory)
  foreach($item in $script:ClientPreparationNames){
    $found=Find-RideWindowsComponentObservation -Inventory $Inventory -Kind $item.Kind -Name $item.Name
    [pscustomobject]@{Kind=$item.Kind;Name=$item.Name;ObservationStatus=$found.Status;StateObserved=if($found.Observation){$found.Observation.StateObserved}else{$null};Selected=$false}
  }
}

function ConvertTo-RideClientSourcePath {
  param($Path)
  if($Path -isnot [string] -or $Path.Length -gt 1024 -or $Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '[*?"<>|%\x00-\x1f]' -or $Path.Substring(2).Contains(':') -or
      $Path -match '(^|[\\/])\.\.?([\\/]|$)'){throw 'SourcePath requires an explicit local drive path without expansion, traversal or alternate streams.'}
  [IO.Path]::GetFullPath($Path)
}

function New-RideClientComponentPreparation {
  <#
  .SYNOPSIS
    Prepare one client-component transition with an explicit source-mode boundary.
  .PARAMETER Inventory
    Supplied schema-1 Windows component observation for the intended machine/build.
  .PARAMETER Kind
    Capability or OptionalFeature, preserving the observed namespace.
  .PARAMETER Name
    Exact observed OpenSSH Client or Telnet Client native identifier. Completion
    uses only captured prioritized names from the supplied Inventory and Kind.
  .PARAMETER DesiredState
    Present or Absent for this independently selected client.
  .PARAMETER SourceMode
    Online respects configured servicing sources. LocalSource supplies an explicit
    local source and blocks Windows Update lookup; configured-source fallback remains
    uninspected, so the mode does not establish network isolation. No default mode.
  .PARAMETER SourcePath
    LocalSource-only local directory path. No file access, matching-build proof or payload
    completeness is inferred from the path. Online forbids a source override.
  .EXAMPLE
    New-RideClientComponentPreparation -Inventory $savedComponents -Kind Capability -Name 'OpenSSH.Client~~~~0.0.1.0' -DesiredState Present -SourceMode LocalSource -SourcePath 'D:\Sources\FOD'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Version-1 preparation with optional command/parameter outline.
  .NOTES
    The DISM Online parameter selects the running OS even in LocalSource source mode.
    LimitAccess blocks Windows Update lookup; it does not prove all configured
    network sources are excluded or that local payloads are complete. No readiness
    is granted until those boundaries, dependencies, policy and native effects pass.
    Feature outlines suppress restart, omit All and never remove payloads. Capability
    cmdlets do not expose NoRestart; the future writer must inspect RestartNeeded
    and never initiate a restart. Pending/unknown states have no command outline.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateSet('Capability','OptionalFeature')][string]$Kind,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        if(-not $fakeBoundParameters.Inventory -or -not $fakeBoundParameters.Kind){return}
        $prefix=([string]$wordToComplete).Trim("'",'"')
        foreach($item in @(Get-RideClientComponentPreparationChoice -Inventory $fakeBoundParameters.Inventory)){
          if($item.Kind -ieq $fakeBoundParameters.Kind -and $item.ObservationStatus -ceq 'Observed' -and $item.Name.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){
            [Management.Automation.CompletionResult]::new(("'"+$item.Name+"'"),$item.Name,'ParameterValue',$item.Name)
          }
        }
      }catch{return}
    })][string]$Name,
    [Parameter(Mandatory)][ValidateSet('Present','Absent')][string]$DesiredState,
    [Parameter(Mandatory)][ValidateSet('Online','LocalSource')][string]$SourceMode,
    [string]$SourcePath)
  $choices=@($script:ClientPreparationNames|Where-Object {$_.Kind -ieq $Kind -and $_.Name -ceq $Name})
  if($choices.Count -ne 1){throw 'Select an exact prioritized client identity in its own provider namespace.'}
  $choice=$choices[0]
  if(($Inventory.SchemaVersion -isnot [int] -and $Inventory.SchemaVersion -isnot [long]) -or $Inventory.SchemaVersion -ne 1 -or $Inventory.ReadyForMutation -isnot [bool] -or $Inventory.ReadyForMutation -or $Inventory.RecoverySupported -isnot [bool] -or $Inventory.RecoverySupported){throw 'Expected a read-only schema-1 component observation.'}
  $context=$Inventory.WindowsContext;$identity=[ordered]@{}
  foreach($field in @('ComputerName','Build','EditionId','InstallationType','ProductType')){
    if($context.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($context.$field) -or $context.$field.Length -gt 255 -or $context.$field -match '[\x00-\x1f]'){throw 'Missing component target context.'}
    $identity[$field]=$context.$field
  }
  if($context.Build -cnotmatch '^[0-9]{4,8}$' -or $context.ProductType -cnotin @('WinNT','ServerNT','LanmanNT') -or $context.NativeProcess -isnot [bool] -or -not $context.NativeProcess -or
      ($context.UpdateBuildRevision -isnot [int] -and $context.UpdateBuildRevision -isnot [long] -and $context.UpdateBuildRevision -isnot [uint32]) -or $context.UpdateBuildRevision -lt 0 -or $context.UpdateBuildRevision -gt [uint32]::MaxValue){throw 'Invalid component target identity/revision.'}
  $identity.UpdateBuildRevision=[long]$context.UpdateBuildRevision;$identity.NativeProcess=$true
  $source=if($SourceMode -ieq 'LocalSource'){
    if(-not $PSBoundParameters.ContainsKey('SourcePath')){throw 'LocalSource mode requires an explicit local source path.'}
    [pscustomobject]@{Mode='LocalSource';Path=(ConvertTo-RideClientSourcePath $SourcePath);WindowsUpdateLookupBlocked=$true;ConfiguredSourceFallback='NotInspected';SourceValidated=$false;NetworkBoundaryVerified=$false;PolicyOverridesAllowed=$false}
  }else{
    if($PSBoundParameters.ContainsKey('SourcePath')){throw 'Online source mode respects configured servicing sources and forbids a source override.'}
    [pscustomobject]@{Mode='Online';Path=$null;WindowsUpdateLookupBlocked=$false;ConfiguredSourceFallback='NotInspected';SourceValidated=$false;NetworkBoundaryVerified=$false;PolicyOverridesAllowed=$false}
  }
  $desired=if($DesiredState -ieq 'Present'){'Present'}else{'Absent'}
  $found=Find-RideWindowsComponentObservation -Inventory $Inventory -Kind $choice.Kind -Name $choice.Name
  $result=[pscustomobject]@{
    SchemaVersion=1;Kind='ClientComponentPreparation';ProviderKind=$choice.Kind;Name=$choice.Name
    WindowsContext=[pscustomobject]$identity;DesiredState=$desired;OriginalState=$null;SourcePolicy=$source
    Status='NeedsObservation';ChangeRequired=$null;Command=$null;Parameters=$null
    ReadyForMutation=$false;RecoverySupported=$false;SelectedByDefault=$false
    Requirements=@('Fresh intended-target/elevation and target support evidence','Pending-reboot, dependencies and management policy preflight','Explicit diagnostic/scratch paths and durable pre-change capture','Verified provider result and literal post-state; no automatic reboot','Product-specific consumer and exact recovery acceptance')
  }
  if($source.Mode -ceq 'LocalSource'){$result.Requirements+=@('Match local source build/edition/architecture/language and required members; prove no network fallback without changing policy')}
  if($found.Status -cne 'Observed'){return $result}
  $state=$found.Observation.StateObserved;$result.OriginalState=$state
  if($context.ProductType -ceq 'LanmanNT'){$result.Status='BlockedDomainController';return $result}
  if($state -cne $choice.PresentState -and $choice.AbsentStates -cnotcontains $state){$result.Status='BlockedPendingOrUnknownState';return $result}
  $isPresent=$state -ceq $choice.PresentState
  $result.ChangeRequired=($isPresent -ne ($desired -ceq 'Present'))
  if(-not $result.ChangeRequired){$result.Status='NoChangeObserved';return $result}
  $parameters=[ordered]@{Online=$true;ErrorAction='Stop'}
  if($choice.Kind -ceq 'Capability'){$parameters.Name=$choice.Name}else{$parameters.FeatureName=@($choice.Name);$parameters.NoRestart=$true}
  $result.Command=if($desired -ceq 'Present'){$choice.Add}else{$choice.Remove}
  if($desired -ceq 'Present' -and $source.Mode -ceq 'LocalSource'){$parameters.Source=@($source.Path);$parameters.LimitAccess=$true}
  if($state -ceq 'DisabledWithPayloadRemoved'){$result.Requirements+=@('Prior feature payload was removed; exact payload/dependency recovery is not established by disabling the feature')}
  if($choice.Kind -ceq 'Capability' -and $desired -ceq 'Absent'){$result.Requirements+=@('Capability removal may need matching payloads to restore; capture/reacquisition and dependency impact remain unverified')}
  $result.Parameters=$parameters;$result.Status='PreparedOutlineOnly'
  $result
}

Export-ModuleMember -Function Get-RideClientComponentPreparationChoice,New-RideClientComponentPreparation
