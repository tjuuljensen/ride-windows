<#
.SYNOPSIS
  Describe selected RIDE configuration for read-only consumers.
.DESCRIPTION
  Converts supplied catalog/profile data into a versioned observation reference.
  Registry values and coordinated value sets retain typed set/remove/keep intent.
  Other handlers and groups remain ReportOnly. Does not import the engine, query
  Windows, expand environment values or provide an apply/recovery plan.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Validated catalog/profile data and independently declared target.
  Version: 0.1.0.
  Changelog: 0.1.0: Add schema-1 desired-configuration reference for read-only use.
.LINK
  ../docs/decisions/0001-configuration-ownership.md
#>
$ErrorActionPreference='Stop'

function Copy-RideReferenceValue {
  param($Value,[int]$Depth=0)
  if($Depth -gt 2){throw 'Desired registry data is too deeply nested.'}
  if($null -eq $Value){return $null}
  if($Value -is [string]){
    if($Value.Length -gt 16384 -or $Value.Contains([char]0)){throw 'Desired registry string exceeds bounds.'}
    return $Value
  }
  if($Value -is [byte] -or $Value -is [int] -or $Value -is [uint32] -or $Value -is [long] -or $Value -is [uint64]){return $Value}
  if($Value -is [array]){
    if($Value.Count -gt 16384){throw 'Desired registry array exceeds bounds.'}
    $copy=@(foreach($item in $Value){Copy-RideReferenceValue -Value $item -Depth ($Depth+1)})
    return ,$copy
  }
  throw 'Desired registry data has an unsupported type.'
}

function New-RideReferenceMapping {
  param([hashtable]$Definition,$Value,[string]$Key)
  foreach($field in @('RegistryPath','ValueName','ValueType')){
    if($Definition[$field] -isnot [string] -or $Definition[$field].Length -gt 2048 -or $Definition[$field] -match '[\x00-\x1f]'){throw 'Invalid registry mapping metadata.'}
  }
  if($Definition.RegistryPath -notmatch '^HK(LM|CU):\\' -or $Definition.ValueType -notin @('DWord','QWord','String','ExpandString','MultiString','Binary')){throw 'Unsupported registry mapping metadata.'}
  $intent='SetValue';$copy=$null
  if($null -eq $Value){$intent='RemoveValue'}
  elseif($Value -is [hashtable]){
    if($Value.Count -ne 1 -or $Value.KeepCurrent -isnot [bool] -or -not $Value.KeepCurrent){throw 'Unsupported desired-value directive.'}
    $intent='KeepCurrent'
  }else{$copy=Copy-RideReferenceValue -Value $Value}
  [pscustomobject]@{
    Key=$Key;RegistryPath=$Definition.RegistryPath;ValueName=$Definition.ValueName
    ValueType=$Definition.ValueType;Intent=$intent;Value=$copy
    RegistryView='NotSpecifiedByCatalog';EnvironmentExpansion='NotPerformed'
  }
}

function ConvertTo-RideDesiredConfiguration {
  <#
  .SYNOPSIS
    Build a read-only reference from explicitly supplied source and target data.
  .PARAMETER Catalog
    Validated schema-1 catalog from the data-only reader.
  .PARAMETER Profile
    Schema-1 profile with explicit selections. Duplicate/conflicting IDs are refused.
  .PARAMETER CatalogSha256
    Exact source catalog hash supplied by the caller; the export tool binds file bytes.
  .PARAMETER ProfileSha256
    Exact source profile hash supplied by the caller.
  .PARAMETER Target
    Declared platform name. No current-machine discovery or support inference.
  .PARAMETER Build
    Declared target build number, used only for declared minimum-build comparison.
  .PARAMETER EditionId
    Declared edition, retained without assuming edition-specific availability.
  .PARAMETER InstallationType
    Declared Windows installation type; Unknown preserves uncertainty.
  .PARAMETER Role
    Declared machine role; no role discovery or inferred security baseline.
  .EXAMPLE
    ConvertTo-RideDesiredConfiguration -Catalog $catalog -Profile $profile -CatalogSha256 $catalogHash -ProfileSha256 $profileHash -Target 'Windows 11' -Build 26100 -EditionId Professional -InstallationType Client -Role Workstation
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 RideDesiredConfigurationReference; never an execution plan.
  .NOTES
    Baseline resolves only where the engine declares it. Removal is override absence,
    not a claim about Windows defaults. Compliance/current state remain Unknown;
    Unsupported/Pending selections stay explicit. Consumer integration is pending.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Catalog,
    [Parameter(Mandatory)][hashtable]$Profile,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$CatalogSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ProfileSha256,
    [Parameter(Mandatory)]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $data=$fakeBoundParameters['Catalog']
        if($data -isnot [hashtable] -or @($data.Operations).Count -gt 2000){return}
        @($data.Operations|ForEach-Object {$_.SupportedTargets;$_.CandidateTargets}) | Sort-Object -Unique |
          Where-Object {$_ -is [string] -and $_.StartsWith($wordToComplete.Trim("'",'"'),[StringComparison]::OrdinalIgnoreCase)} | ForEach-Object {
            [Management.Automation.CompletionResult]::new(("'"+$_.Replace("'","''")+"'"),$_,'ParameterValue',$_)
          }
      }catch{}
    })]
    [ValidateLength(1,255)][string]$Target,
    [Parameter(Mandatory)][ValidateRange(1000,99999999)][int]$Build,
    [Parameter(Mandatory)][ValidateLength(1,255)][string]$EditionId,
    [Parameter(Mandatory)][ValidateSet('Client','Server','Server Core','Unknown')][string]$InstallationType,
    [Parameter(Mandatory)][ValidateSet('Workstation','MemberServer','DomainController','Unknown')][string]$Role
  )
  if($Catalog.SchemaVersion -ne 1 -or $Profile.SchemaVersion -ne 1 -or $Profile.Name -isnot [string] -or
      $Profile.Name.Length -gt 255 -or @($Profile.Operations).Count -lt 1 -or @($Profile.Operations).Count -gt 2000 -or
      @($Catalog.Operations).Count+@($Catalog.Groups).Count -gt 2000){throw 'Invalid or excessive reference source schema.'}
  $index=@{};$groups=@{}
  foreach($op in $Catalog.Operations){
    if($op -isnot [hashtable] -or $op.Id -notmatch '^[a-z][a-z0-9.-]{1,159}$' -or $index.ContainsKey($op.Id)){throw 'Invalid or duplicate catalog operation.'}
    $index[$op.Id]=$op
  }
  foreach($group in $Catalog.Groups){
    if($group -isnot [hashtable] -or $group.Id -notmatch '^[a-z][a-z0-9.-]{1,159}$' -or $index.ContainsKey($group.Id) -or $groups.ContainsKey($group.Id)){throw 'Invalid or duplicate catalog group.'}
    $groups[$group.Id]=$group
  }
  $seen=@{};$records=@(foreach($selection in $Profile.Operations){
    if($selection -isnot [hashtable] -or $selection.Id -isnot [string] -or $selection.State -isnot [string] -or
        -not $selection.State -or $selection.State.Length -gt 128 -or $seen.ContainsKey($selection.Id)){throw 'Missing or duplicate/conflicting profile selection.'}
    foreach($key in $selection.Keys){if($key -notin @('Id','State','Variant')){throw 'Unknown profile selection field.'}}
    $seen[$selection.Id]=$true
    $op=$index[$selection.Id];$group=$groups[$selection.Id]
    if($null -eq $op -and $null -eq $group){throw 'Profile refers to an unknown catalog identity.'}
    if($group){
      if($selection.State -notin @('Present','Absent') -or $selection.ContainsKey('Variant')){throw 'Invalid group selection.'}
      $members=@(foreach($id in $group.Members){if(-not $index.ContainsKey($id)){throw 'Unknown group member.'};[string]$index[$id].Id})
      [pscustomobject]@{Id=$group.Id;RecordType='GroupSelection';Kind='Group';Scope=$null;RequestedState=$selection.State;ResolvedState=$selection.State;Variant=$null;DeclaredTargetStatus='Unknown';ReferenceMode='ReportOnly';Reason='Group lifecycle is not a configuration observation mapping';Mappings=@();Members=$members;CurrentState='Unknown';Compliance='Unknown'}
      continue
    }
    $state=$selection.State
    if($state -eq 'Baseline' -and $op.Kind -in @('RegistryValue','RegistryValueSet','ShellFolder','ProfileSetting')){
      if(-not $op.BaselineState){throw 'Operation does not declare a baseline.'};$state=$op.BaselineState
    }
    if($op.States -is [hashtable]){
      if(-not $op.States.ContainsKey($state)){throw 'Profile requests an undeclared operation state.'}
      $state=[string]@($op.States.Keys|Where-Object {$_ -ieq $state})[0]
    }elseif($op.Kind -in @('Package','DefenderExclusion')){
      if($state -notin @('Present','Absent')){throw 'Presence operation requires Present or Absent.'}
    }else{throw 'Operation has no supported desired-state contract.'}
    $variant=$null
    if($selection.ContainsKey('Variant')){
      if($op.Kind -ne 'Package' -or $selection.Variant -isnot [string] -or
          ($op.Variants -and -not $op.Variants.ContainsKey($selection.Variant)) -or
          (-not $op.Variants -and $selection.Variant -ne 'installed')){throw 'Invalid explicit package variant.'}
      $variant=$selection.Variant
    }
    $status='DeclaredSupported';$reason='Live applicability, policy precedence and consumer verification are unknown'
    if($op.PendingAcceptance){$status='PendingAcceptance';$reason='Candidate metadata does not establish supported behavior'}
    elseif($Target -notin $op.SupportedTargets){$status='NotApplicable';$reason='Target not in declared SupportedTargets'}
    elseif($op.MinimumBuild -and $Build -lt $op.MinimumBuild){$status='NotApplicable';$reason='Below declared MinimumBuild'}
    elseif($op.RequiresDesktopExperience -and $Target -like 'Windows Server*'){
      if($InstallationType -eq 'Unknown'){$status='Unknown';$reason='Desktop Experience availability is unknown'}
      elseif($InstallationType -ne 'Server'){$status='NotApplicable';$reason='Requires Windows Server Desktop Experience'}
    }
    $scope=$op.Scope
    if($op.Kind -eq 'Package'){
      $scope=$null;$status='Unknown';$reason='Package variant, destination and lifecycle are not resolved by this reference'
    }
    $mappings=@();$mode='ReportOnly'
    if($op.Kind -in @('RegistryValue','RegistryValueSet')){
      $mode='DeclaredRegistryIntent'
      if($op.Kind -eq 'RegistryValue'){$mappings=@(New-RideReferenceMapping -Definition $op -Value $op.States[$state] -Key 'Value')}
      else{
        $data=$op.States[$state]
        if($data -isnot [hashtable] -or @($op.RegistryValues).Count -gt 64 -or $data.Count -ne @($op.RegistryValues).Count){throw 'Invalid coordinated registry state.'}
        $keys=@{};$mappings=@(foreach($value in $op.RegistryValues){
          if($value.Key -isnot [string] -or -not $value.Key -or $keys.ContainsKey($value.Key) -or -not $data.ContainsKey($value.Key)){throw 'Invalid coordinated registry component.'}
          $keys[$value.Key]=$true
          New-RideReferenceMapping -Definition $value -Value $data[$value.Key] -Key $value.Key
        })
      }
    }
    [pscustomobject]@{
      Id=$op.Id;RecordType='OperationSelection';Kind=$op.Kind;Scope=$scope
      RequestedState=$selection.State;ResolvedState=$state;Variant=$variant
      DeclaredTargetStatus=$status;ReferenceMode=$mode;Reason=$reason;Mappings=$mappings;Members=@()
      CurrentState='Unknown';Compliance='Unknown'
    }
  })
  [pscustomobject]@{
    SchemaVersion=1;Kind='RideDesiredConfigurationReference';ProducerVersion='0.1.0';GeneratedAtUtc=[DateTime]::UtcNow.ToString('o')
    ConfigurationOwner='RIDE';ConsumerPermission='ObserveEvaluateReportOnly'
    Source=[pscustomobject]@{CatalogSha256=$CatalogSha256.ToLowerInvariant();ProfileSha256=$ProfileSha256.ToLowerInvariant();ProfileName=$Profile.Name}
    DeclaredTarget=[pscustomobject]@{Name=$Target;Build=$Build;EditionId=$EditionId;InstallationType=$InstallationType;Role=$Role;Observed=$false}
    Selections=$records;IncludesLiveState=$false;IncludesMeasurementThresholds=$false
    ReadyForMutation=$false;RecoverySupported=$false;ConsumerAcceptance='Pending'
  }
}
Export-ModuleMember -Function ConvertTo-RideDesiredConfiguration
