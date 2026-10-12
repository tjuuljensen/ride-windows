<#
.SYNOPSIS
  Present declared setting scope, behavior and requirements consistently.
.DESCRIPTION
  Reads catalog metadata without loading handlers or inferring policy behavior
  from registry paths. Missing evidence remains visible as unverified. Optional
  execution identity identifies the account whose user scope would be used;
  it does not establish that this is the intended interactive user.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add additive, read-only setting presentation metadata.
#>

$script:ModuleVersion = '0.1.0'

function Get-RideSettingExecutionIdentity {
  try {
    $account = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { '{0} ({1}); intended user not verified' -f $account.Name, $account.User.Value }
    finally { $account.Dispose() }
  }
  catch { 'Execution account unavailable; intended user not verified' }
}

function Get-RideSettingPresentation {
  <#
  .SYNOPSIS
    Return catalog-backed setting presentation with explicit evidence gaps.
  .PARAMETER Operation
    Declarative operation or group. Published scope is never changed.
  .PARAMETER IncludeExecutionIdentity
    Include the current Windows execution account and SID for user settings.
    Omit for discovery, completion and generated documentation.
  .EXAMPLE
    Get-RideSettingPresentation -Operation $operation
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Presentation fields.
  .NOTES
    Read-only; no Windows handlers or effective-policy queries are invoked.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation, [switch] $IncludeExecutionIdentity)

  $isSetting = $Operation.Kind -and $Operation.Kind -notin @('Package', 'Artifact')
  $isSelection = -not $Operation.ContainsKey('Kind')
  $metadata = $Operation.SettingPresentation
  $behaviorNames = @{
    Preference = 'Preference'; EnforcedPolicy = 'Enforced policy'
    RecommendedPolicy = 'Recommended policy'; Configuration = 'Feature configuration'
    Unverified = 'Unverified'
  }
  $identity = $null
  if ($isSetting -and $Operation.Scope -eq 'User' -and $IncludeExecutionIdentity) {
    $identity = Get-RideSettingExecutionIdentity
  }
  [pscustomobject]@{
    AppliesTo = if ($isSelection) { 'Defined by selected members; inspect group details or the profile plan' } elseif (-not $isSetting) { $null } elseif ($metadata.AppliesTo) { $metadata.AppliesTo } elseif ($Operation.Scope -eq 'User') { 'Current Windows execution user' } else { 'Device (machine scope); feature coverage unverified' }
    Behavior = if ($isSelection) { 'Varies by member' } elseif (-not $isSetting) { $null } elseif ($metadata.Behavior -and $behaviorNames.ContainsKey($metadata.Behavior)) { $behaviorNames[$metadata.Behavior] } else { 'Unverified' }
    GuiEffect = if ($isSelection) { 'Defined by each member' } elseif (-not $isSetting) { $null } elseif ($metadata.GuiEffect) { $metadata.GuiEffect } else { 'Unverified; scope and elevation do not establish GUI editability' }
    GuiPath = if ($isSetting -and $metadata.GuiPath) { $metadata.GuiPath } else { $null }
    Requirements = if ($isSelection) { 'All selected member requirements apply; inspect details or the profile plan' } elseif (-not $isSetting) { $null } elseif ($metadata.Requirements) { @($metadata.Requirements) -join '; ' } else { 'Edition, build, account, license and hardware requirements not yet reviewed' }
    OtherSupportedChoices = if ($isSelection) { 'Defined by each member; selection does not change a published scope' } elseif (-not $isSetting) { $null } elseif ($metadata.OtherSupportedChoices) { @($metadata.OtherSupportedChoices) -join '; ' } else { 'Alternate scope or policy level not yet reviewed; this ID has fixed scope' }
    EffectivePolicy = if ($isSetting) { 'Not inspected; configured values do not establish effective policy or its source' } else { $null }
    ExecutionIdentity = $identity
  }
}

function Add-RideSettingPresentation {
  <#
  .SYNOPSIS
    Add consistent setting presentation to an existing discovery or live row.
  .PARAMETER InputObject
    Row to enrich. Existing lifecycle fields are preserved.
  .PARAMETER Operation
    Declarative operation or group that owns the row.
  .PARAMETER IncludeExecutionIdentity
    Include the account used by live user-scope commands.
  .EXAMPLE
    $row | Add-RideSettingPresentation -Operation $operation
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Enriched row.
  .NOTES
    Read-only. Does not change operation metadata, state stores or scope.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline)][psobject] $InputObject,
    [Parameter(Mandatory)][hashtable] $Operation,
    [switch] $IncludeExecutionIdentity
  )
  process {
    if ($Operation.ContainsKey('Kind')) {
      $InputObject | Add-Member -NotePropertyName Scope -NotePropertyValue $Operation.Scope -Force
      $InputObject | Add-Member -NotePropertyName RequiresAdmin -NotePropertyValue $Operation.RequiresAdmin -Force
    }
    $presentation = Get-RideSettingPresentation -Operation $Operation -IncludeExecutionIdentity:$IncludeExecutionIdentity
    foreach ($property in $presentation.PSObject.Properties) {
      $InputObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
    }
    $InputObject
  }
}

Export-ModuleMember -Function Get-RideSettingPresentation, Add-RideSettingPresentation
