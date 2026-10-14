<#
.SYNOPSIS
  Discover, plan and manage explicit intended-user Store app groups.
.DESCRIPTION
  Separate app-registration workflow using catalog IDs, per-app results and
  user-owned records. No downloads, AllUsers changes, provisioning or policy writes.
  Candidate targets remain blocked until applicable acceptance. Current uses
  the unelevated signed-in user's own desktop console; alternate-admin Store
  handoff is explicit; its launch receipt is not actual completion or native acceptance.
.PARAMETER Command
  List (default), Inspect, Plan, Uninstall or Reinstall; Tab completes choices.
.PARAMETER Id
  Exact Store app or Store group catalog ID. Tab reads the same catalog only.
.PARAMETER Action
  Uninstall (default) or Reinstall for Plan. Other commands derive their action.
.PARAMETER ExpectedUserSid
  Explicit intended user's SID for live planning/actions; confirm with whoami /user.
.PARAMETER RemovalRunId
  User-owned saved Store removal run for Reinstall; Tab reads bounded local run names.
.PARAMETER UserContext
  Current (default) or Desktop. Desktop launches the existing signed-in user's
  process in this session; saved records are read/written only by that user.
.PARAMETER Help
  Display native help without importing operational modules.
.PARAMETER Version
  Print the version without operational work.
.EXAMPLE
  .\tools\Invoke-RideStoreApps.ps1 List
.EXAMPLE
  .\tools\Invoke-RideStoreApps.ps1 Plan solution.store-consumer-apps -ExpectedUserSid S-1-5-21-1-2-3-1001
.EXAMPLE
  .\tools\Invoke-RideStoreApps.ps1 Uninstall app.news -ExpectedUserSid S-1-5-21-1-2-3-1001 -WhatIf
.INPUTS
  None.
.OUTPUTS
  PSCustomObject. Catalog discovery, per-app plans or partial action results.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Appx cmdlets; accepted target; unelevated intended desktop user.
  State: LocalApplicationData/RIDE/State/StoreApps; not a setting restore run.
  Recovery: Retained-payload re-registration only; no exact data/version recovery.
  Owner: RIDE-Windows maintainers. Version: 0.2.0.
  Changelog: 0.2.0: Add explicit source-bound desktop-user handoff for Store actions.
    0.1.0: Add catalog-derived Store discovery/completion and guarded actions.
.LINK
  docs/store-app-groups.md
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
  [Parameter(Position=0)][ValidateSet('List','Inspect','Plan','Uninstall','Reinstall')][string]$Command='List',
  [Parameter(Position=1)][ArgumentCompleter({
    param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{
      $scriptPath=$commandAst.CommandElements[0].Value
      if(-not(Test-Path -LiteralPath $scriptPath -PathType Leaf)){$scriptPath=(Get-Command $commandName -CommandType ExternalScript -ErrorAction Stop).Source}
      $root=Split-Path -Parent (Split-Path -Parent $scriptPath)
      $reader=Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force -PassThru -Scope Local -ErrorAction Stop
      $c=& $reader {param($path) Import-RideCatalogData -Path $path} (Join-Path $root 'catalog/operations.psd1')
      @($c.Operations|Where-Object Kind -eq StoreApp|ForEach-Object Id)+@($c.Groups|Where-Object Workflow -eq StoreApps|ForEach-Object Id)|Sort-Object -Unique|Where-Object {$_.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)}|ForEach-Object {[Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',$_)}
    }catch{}
  })][string]$Id,
  [ValidateSet('Uninstall','Reinstall')][string]$Action='Uninstall',
  [ValidatePattern('^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$')][string]$ExpectedUserSid,
  [ArgumentCompleter({
    param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{
      if($fakeBoundParameters.UserContext -eq 'Desktop'){return}
      $root=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RIDE/State/StoreApps'
      @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop|Select-Object -First 500)|Where-Object {$_.Name -match '^[0-9a-f]{32}$' -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $_.Name.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)}|ForEach-Object {[Management.Automation.CompletionResult]::new($_.Name,$_.Name,'ParameterValue',$_.Name)}
    }catch{}
  })][string]$RemovalRunId,
  [ValidateSet('Current','Desktop')][string]$UserContext='Current',
  [switch]$Help,[switch]$Version
)
$ErrorActionPreference='Stop'
if($Version){'0.2.0';return}
if($Help){Get-Help $PSCommandPath -Full;return}
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
$catalog=Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')
if($Command -eq 'List'){
  if($Id -or $ExpectedUserSid -or $RemovalRunId -or $UserContext -ne 'Current' -or $PSBoundParameters.ContainsKey('Action')){throw 'List accepts no live-action selection.'}
  @($catalog.Operations|Where-Object Kind -eq StoreApp)+@($catalog.Groups|Where-Object Workflow -eq StoreApps)|ForEach-Object {[pscustomobject]@{Id=$_.Id;Name=$_.Name;Actions=@($_.Actions);Members=@($_.Members);SupportedTargets=@($_.SupportedTargets);PendingAcceptance=$_.PendingAcceptance;Recovery=$_.Rollback}}
  return
}
if(-not $Id -or -not $ExpectedUserSid){throw 'Live Store commands require -Id and explicit -ExpectedUserSid.'}
if($Command -ne 'Plan' -and $PSBoundParameters.ContainsKey('Action')){throw '-Action is only used by Plan.'}
Import-Module (Join-Path $root 'modules/RIDE.StoreApps.psm1') -Force -ErrorAction Stop
if($UserContext -eq 'Desktop'){
  if($Command -notin @('Plan','Uninstall','Reinstall')){throw 'Desktop Store handoff supports Plan, Uninstall and Reinstall.'}
  $handoff=@{Command=$Command;Id=$Id;ExpectedUserSid=$ExpectedUserSid;RemovalRunId=$RemovalRunId;Action=$Action;WhatIf=[bool]$WhatIfPreference}
  if($PSBoundParameters.ContainsKey('Confirm')){$handoff.Confirm=[bool]$PSBoundParameters.Confirm}
  Start-RideStoreDesktopHandoff @handoff
  return
}
if($Command -eq 'Inspect'){
  if($RemovalRunId){throw 'Inspect uses no removal record.'}
  Get-RideStoreAppPlan -Id $Id -Action Uninstall -ExpectedUserSid $ExpectedUserSid|ForEach-Object {[pscustomobject]@{OperationId=$_.Operation.Id;Live=$_.Before;Refusals=$_.Refusals;Target=$_.Target;Recovery=$_.Recovery}}
  return
}
$effectiveAction=if($Command -eq 'Plan'){$Action}else{$Command}
if($effectiveAction -eq 'Uninstall' -and $RemovalRunId){throw 'Uninstall uses no prior removal record.'}
if($effectiveAction -eq 'Reinstall' -and -not $RemovalRunId){throw 'Reinstall requires an owned -RemovalRunId.'}
$actionParameters=@{Id=$Id;Action=$effectiveAction;ExpectedUserSid=$ExpectedUserSid;RemovalRunId=$RemovalRunId}
if($Command -eq 'Plan'){Get-RideStoreAppPlan @actionParameters;return}
$safety=@{WhatIf=[bool]$WhatIfPreference}
if($PSBoundParameters.ContainsKey('Confirm')){$safety.Confirm=[bool]$PSBoundParameters.Confirm}
Invoke-RideStoreAppAction @actionParameters @safety
