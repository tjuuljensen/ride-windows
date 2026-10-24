<#
.SYNOPSIS
  Apply and restore selected OpenSSH Client and Telnet Client component states.
.DESCRIPTION
  Uses a fresh local component observation, explicit servicing-source mode, a protected
  machine snapshot, ShouldProcess, literal post-state readback and no automatic restart.
  This candidate is not connected to the catalog; payload identity and exact recovery are
  not guaranteed by DISM state transitions.
.PARAMETER ExpectedComputerName
  Local computer name to compare with the fresh inventory context.
.PARAMETER ExpectedBuild
  Exact Windows build to compare with the fresh inventory context.
.PARAMETER ExpectedEditionId
  Exact Windows EditionID to compare with the fresh inventory context.
.PARAMETER LogDirectory
  Existing local directory for unique DISM inventory log and scratch files.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Existing elevation, native process, one selected client component.
  Recovery: Saved machine-scope state restores the prior literal servicing state only
  when doing so does not remove a component payload without a validated recovery source.
  The snapshot does not retain payload bytes or version.
  Version: 0.3.3.
  Changelog: 0.3.3: Validate the exact non-satellite OpenSSH Client CAB identity, architecture and Windows build before LocalSource servicing and restore.
    Telnet LocalSource remains blocked until its optional-feature source is independently validated.
    0.3.2: Refuse LocalSource transitions and Present restores until servicing source validation exists.
    0.3.1: Block restore paths that would remove an unverified component payload.
    0.3.0: Restrict the candidate to Windows 11 builds and block unverified removal.
  0.2.0: Use LocalSource mode to identify an explicit source without claiming network isolation.
  0.1.0: Add guarded client-component servicing and state recovery candidate.
.LINK
  ../docs/windows-component-inventory.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.ClientComponentPreparation.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.ComponentInventory.psm1') -ErrorAction Stop

function Get-RideClientComponentStateDirectory {
  Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RIDE/State/ClientComponents'
}

function Initialize-RideClientComponentStateDirectory {
  $root=Get-RideClientComponentStateDirectory
  New-Item -ItemType Directory -Path $root -Force | Out-Null
  $item=Get-Item -LiteralPath $root -Force
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Component state directory cannot be a reparse point.'}
  $acl=Get-Acl -LiteralPath $root
  $acl.SetAccessRuleProtection($true,$false)
  foreach($rule in @($acl.Access)){$acl.RemoveAccessRuleAll($rule)}
  foreach($sidText in @('S-1-5-18','S-1-5-32-544')){
    $sid=New-Object Security.Principal.SecurityIdentifier($sidText)
    $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $root -AclObject $acl
  $root
}

function Test-RideClientComponentPendingReboot {
  $rebootKeyPaths=@(
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
  )
  foreach($path in $rebootKeyPaths){
    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path,$false)
    if($key){$key.Dispose();return $true}
  }
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager',$false)
  if(-not $key){throw 'Unable to inspect pending file-rename servicing state.'}
  try{$pending=$key.GetValue('PendingFileRenameOperations',$null)}finally{$key.Dispose()}
  return [bool](@($pending|Where-Object {$_}).Count)
}

function Get-RideClientComponentFreshState {
  param([string]$Kind,[string]$Name,[string]$ExpectedComputerName,[string]$ExpectedBuild,[string]$ExpectedEditionId,[string]$LogDirectory)
  $inventory=Get-RideWindowsComponentInventory -Kind $Kind -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -LogDirectory $LogDirectory
  if($inventory.WindowsContext.ProductType -cne 'WinNT' -or $inventory.WindowsContext.InstallationType -cne 'Client') {throw 'Client component servicing is limited to a Windows client installation; Server targets are not declared.'}
  $found=Find-RideWindowsComponentObservation -Inventory $inventory -Kind $Kind -Name $Name
  if($found.Status -ne 'Observed'){throw "Fresh $Kind observation for '$Name' is $($found.Status); refusing servicing."}
  [pscustomobject]@{Inventory=$inventory;State=[string]$found.Observation.StateObserved}
}

function Get-RideClientComponentSourceArchitecture {
  $architecture=if($env:PROCESSOR_ARCHITEW6432){$env:PROCESSOR_ARCHITEW6432}else{$env:PROCESSOR_ARCHITECTURE}
  switch -Regex ($architecture) {
    '^(AMD64|x64)$' { return 'amd64' }
    '^(ARM64|AARCH64)$' { return 'arm64' }
    '^(x86|i386|i686)$' { return 'x86' }
    default { throw 'Unable to determine a supported native Windows source architecture.' }
  }
}

function Get-RideClientComponentSourcePackageMetadata {
  param([Parameter(Mandatory)][string]$LiteralPath)
  & Dism\Get-WindowsPackage -PackagePath $LiteralPath -ErrorAction Stop
}

function Test-RideClientComponentLocalSource {
  param([Parameter(Mandatory)][string]$Kind,[Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$SourcePath,[Parameter(Mandatory)][string]$ExpectedBuild)
  if($Kind -cne 'Capability' -or $Name -cne 'OpenSSH.Client~~~~0.0.1.0'){
    throw 'LocalSource validation is currently available only for the non-satellite OpenSSH Client capability; Telnet source validation is not implemented.'
  }
  if(-not (Test-Path -LiteralPath $SourcePath -PathType Container)){throw 'LocalSource servicing source directory does not exist.'}
  $root=Get-Item -LiteralPath $SourcePath -Force
  if($root.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'LocalSource root cannot be a reparse point.'}
  $architecture=Get-RideClientComponentSourceArchitecture
  $cabName="OpenSSH-Client-Package~31bf3856ad364e35~$architecture~~.cab"
  $cabPath=Join-Path $root.FullName $cabName
  if(-not (Test-Path -LiteralPath $cabPath -PathType Leaf)){throw "LocalSource must contain the exact OpenSSH Client CAB for architecture '$architecture'."}
  $cab=Get-Item -LiteralPath $cabPath -Force
  if(($cab.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $cab.Length -le 0){throw 'OpenSSH Client source CAB is a reparse point or empty.'}
  $metadata=@(Get-RideClientComponentSourcePackageMetadata -LiteralPath $cab.FullName)
  if($metadata.Count -ne 1 -or $metadata[0].PackageName -isnot [string]){throw 'OpenSSH Client source CAB metadata is missing or ambiguous.'}
  $identityPattern='^OpenSSH-Client-Package~31bf3856ad364e35~'+[regex]::Escape($architecture)+'~~10\.0\.(?<Build>[0-9]+)\.[0-9]+$'
  if($metadata[0].PackageName -notmatch $identityPattern){throw 'OpenSSH Client CAB identity does not match the expected publisher package and architecture.'}
  if($Matches.Build -cne $ExpectedBuild){throw "OpenSSH Client CAB build '$($Matches.Build)' does not match target build '$ExpectedBuild'."}
  $hash=Get-FileHash -LiteralPath $cab.FullName -Algorithm SHA256 -ErrorAction Stop
  [pscustomobject]@{Path=$root.FullName;CabPath=$cab.FullName;Architecture=$architecture;PackageName=$metadata[0].PackageName;Sha256=$hash.Hash.ToLowerInvariant();Validated=$true;NetworkBoundaryVerified=$false;ConfiguredSourceFallback='NotInspected'}
}

function Invoke-RideClientComponentNativeTransition {
  param([string]$Kind,[string]$Name,[ValidateSet('Present','Absent')][string]$DesiredState,[ValidateSet('Online','LocalSource')][string]$SourceMode,[string]$SourcePath,[switch]$RestoreRemovedPayload)
  $parameters=@{Online=$true;ErrorAction='Stop'}
  if($Kind -eq 'Capability'){
    $parameters.Name=$Name
    if($DesiredState -eq 'Present'){
      if($SourceMode -eq 'LocalSource'){$parameters.Source=@($SourcePath);$parameters.LimitAccess=$true}
      & Dism\Add-WindowsCapability @parameters
    }else{& Dism\Remove-WindowsCapability @parameters}
  }else{
    $parameters.FeatureName=@($Name);$parameters.NoRestart=$true
    if($DesiredState -eq 'Present'){
      if($SourceMode -eq 'LocalSource'){$parameters.Source=@($SourcePath);$parameters.LimitAccess=$true}
      & Dism\Enable-WindowsOptionalFeature @parameters
    }else{
      if($RestoreRemovedPayload){$parameters.Remove=$true}
      & Dism\Disable-WindowsOptionalFeature @parameters
    }
  }
}

function Save-RideClientComponentSnapshot {
  param($Record)
  $root=Initialize-RideClientComponentStateDirectory
  $runId=[guid]::NewGuid().ToString('N')
  $path=Join-Path $root ($runId+'.json')
  $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject $Record -Depth 10 -Compress))
  if($bytes.Length -gt 65536){throw 'Client component snapshot exceeds 64 KiB.'}
  $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  [pscustomobject]@{RunId=$runId;Path=$path}
}

function Read-RideClientComponentSnapshot {
  param([string]$RunId)
  if($RunId -notmatch '^[0-9a-fA-F]{32}$'){throw 'RunId must be a 32-character hexadecimal saved component ID.'}
  $path=Join-Path (Get-RideClientComponentStateDirectory) ($RunId+'.json')
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw 'Saved client component state was not found.'}
  $item=Get-Item -LiteralPath $path -Force
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 65536){throw 'Saved client component state path or size is invalid.'}
  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
  try{$bytes=[byte[]]::new([int]$stream.Length);$offset=0;while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'Saved state changed while being read.'};$offset+=$count}}finally{$stream.Dispose()}
  $record=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json -ErrorAction Stop
  $supportedPair=($record.ProviderKind -ceq 'Capability' -and $record.Name -ceq 'OpenSSH.Client~~~~0.0.1.0') -or ($record.ProviderKind -ceq 'OptionalFeature' -and $record.Name -ceq 'TelnetClient')
  $validPriorState=if($record.ProviderKind -ceq 'Capability'){$record.BeforeState -cin @('NotPresent','Installed')}else{$record.BeforeState -cin @('Disabled','DisabledWithPayloadRemoved','Enabled')}
  $validDesired=$record.DesiredState -cin @('Present','Absent')
  $validSource=$record.SourceMode -cin @('Online','LocalSource') -and (($record.SourceMode -ceq 'Online' -and $null -eq $record.SourcePath) -or ($record.SourceMode -ceq 'LocalSource' -and $record.SourcePath -is [string] -and $record.SourcePath.Length -gt 0))
  $expectedState=if($validPriorState -and $validDesired){Get-RideClientComponentExpectedState -Kind $record.ProviderKind -DesiredState $record.DesiredState -PriorState $record.BeforeState}else{$null}
  if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'ClientComponentState' -or -not $supportedPair -or -not $validPriorState -or -not $validDesired -or -not $validSource -or $record.ExpectedState -cne $expectedState -or $record.ProductType -cne 'WinNT' -or $record.ExactPayloadRecoverySupported -cne $false){throw 'Saved client component state does not match the supported provider, client identity, source and state schema.'}
  if($record.SourceMode -ceq 'LocalSource'){$record.SourcePath=ConvertTo-RideClientComponentRestoreSourcePath $record.SourcePath}
  $record
}

function Get-RideClientComponentExpectedState {
  param([string]$Kind,[string]$DesiredState,[string]$PriorState)
  if($Kind -eq 'Capability'){return $(if($DesiredState -eq 'Present'){'Installed'}else{'NotPresent'})}
  if($DesiredState -eq 'Present'){return 'Enabled'}
  if($PriorState -eq 'DisabledWithPayloadRemoved'){return 'DisabledWithPayloadRemoved'}
  'Disabled'
}

function ConvertTo-RideClientComponentRestoreSourcePath {
  param([string]$Path)
  if($Path -isnot [string] -or $Path.Length -gt 1024 -or $Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '[*?"<>|%\x00-\x1f]' -or $Path.Substring(2).Contains(':') -or $Path -match '(^|[\\/])\.\.?([\\/]|$)'){throw 'Saved LocalSource path is invalid.'}
  [IO.Path]::GetFullPath($Path)
}

function Invoke-RideClientComponentTransition {
  <#
  .SYNOPSIS
    Service one explicitly selected OpenSSH Client or Telnet Client state.
  .DESCRIPTION
    Requires fresh local identity/provider observations, refuses a pending reboot,
    captures the prior literal state before calling DISM, verifies post-state and never
    initiates restart. Source and policy evidence remain attached to the saved run.
  .PARAMETER Kind
    Exact provider namespace, Capability or OptionalFeature.
  .PARAMETER Name
    OpenSSH.Client~~~~0.0.1.0 or TelnetClient only.
  .PARAMETER DesiredState
    Present or Absent for the one selected client component.
  .PARAMETER SourceMode
    Explicit Online or LocalSource source mode; there is no default. LocalSource blocks
    Windows Update lookup, while configured-source fallback remains uninspected.
  .PARAMETER SourcePath
    Existing local drive source for LocalSource install; Windows Update lookup is blocked but configured-source fallback is not inspected.
  .EXAMPLE
    Invoke-RideClientComponentTransition -Kind Capability -Name 'OpenSSH.Client~~~~0.0.1.0' -DesiredState Present -SourceMode Online -ExpectedComputerName $env:COMPUTERNAME -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory C:\Evidence -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. RunId, literal result, restart requirement and recovery fidelity.
  .NOTES
    Candidate-only. Exact component payload/version recovery and target support are not claimed.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidateSet('Capability','OptionalFeature')][string]$Kind,
    [Parameter(Mandatory)][ValidateSet('OpenSSH.Client~~~~0.0.1.0','TelnetClient')][string]$Name,
    [Parameter(Mandatory)][ValidateSet('Present','Absent')][string]$DesiredState,
    [Parameter(Mandatory)][ValidateSet('Online','LocalSource')][string]$SourceMode,
    [string]$SourcePath,
    [Parameter(Mandatory)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][string]$LogDirectory)
  if([long]$ExpectedBuild -lt 22000){throw 'Client component candidate is limited to Windows 11 builds; older Windows client targets are not declared.'}
  $preflightInventory=[pscustomobject]@{SchemaVersion=1;Kind='WindowsComponentObservation';ReadyForMutation=$false;RecoverySupported=$false;WindowsContext=[pscustomobject]@{ComputerName=$ExpectedComputerName;Build=$ExpectedBuild;EditionId=$ExpectedEditionId;InstallationType='Client';ProductType='WinNT';NativeProcess=$true;UpdateBuildRevision=0};Providers=@()}
  $planArguments=@{Inventory=$preflightInventory;Kind=$Kind;Name=$Name;DesiredState=$DesiredState;SourceMode=$SourceMode}
  if($PSBoundParameters.ContainsKey('SourcePath')){$planArguments.SourcePath=$SourcePath}
  $plan=New-RideClientComponentPreparation @planArguments
  if($plan.Status -notin @('NeedsObservation','PreparedOutlineOnly','NoChangeObserved')){throw "Component preflight is $($plan.Status)."}
  if($SourceMode -eq 'Online' -and $PSBoundParameters.ContainsKey('SourcePath')){throw 'Online mode forbids a SourcePath override.'}
  $fresh=Get-RideClientComponentFreshState -Kind $Kind -Name $Name -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -LogDirectory $LogDirectory
  $statePlanArguments=@{Inventory=$fresh.Inventory;Kind=$Kind;Name=$Name;DesiredState=$DesiredState;SourceMode=$SourceMode}
  if($PSBoundParameters.ContainsKey('SourcePath')){$statePlanArguments.SourcePath=$SourcePath}
  $statePlan=New-RideClientComponentPreparation @statePlanArguments
  if($statePlan.Status -eq 'NoChangeObserved'){return [pscustomobject]@{Status='NoChange';Kind=$Kind;Name=$Name;State=$fresh.State;RunId=$null;RestartNeeded=$false;PostStateVerified=$true;ExactPayloadRecoverySupported=$false}}
  if($statePlan.Status -ne 'PreparedOutlineOnly'){throw "Component state preflight is $($statePlan.Status); refusing servicing."}
  $sourceValidation=$null
  if($SourceMode -eq 'LocalSource' -and $DesiredState -eq 'Present'){$sourceValidation=Test-RideClientComponentLocalSource -Kind $Kind -Name $Name -SourcePath $plan.SourcePolicy.Path -ExpectedBuild $ExpectedBuild}
  if($DesiredState -eq 'Absent'){throw 'Component removal is unavailable until a matching recovery source is validated; the current candidate cannot establish source identity or completeness.'}
  if(Test-RideClientComponentPendingReboot){throw 'A Windows servicing restart is pending; complete it before component servicing.'}
  if(-not $PSCmdlet.ShouldProcess("$ExpectedComputerName / $Kind / $Name","Set component state to $DesiredState")){return [pscustomobject]@{Status='WhatIf';Kind=$Kind;Name=$Name;State=$fresh.State;RunId=$null;RestartNeeded=$false;PostStateVerified=$false;ExactPayloadRecoverySupported=$false}}
  $record=[pscustomobject]@{SchemaVersion=1;Kind='ClientComponentState';ComputerName=$fresh.Inventory.WindowsContext.ComputerName;Build=$fresh.Inventory.WindowsContext.Build;EditionId=$fresh.Inventory.WindowsContext.EditionId;UpdateBuildRevision=$fresh.Inventory.WindowsContext.UpdateBuildRevision;ProductType=$fresh.Inventory.WindowsContext.ProductType;ProviderKind=$Kind;Name=$Name;BeforeState=$fresh.State;DesiredState=$DesiredState;ExpectedState=(Get-RideClientComponentExpectedState $Kind $DesiredState $fresh.State);SourceMode=$SourceMode;SourcePath=$plan.SourcePolicy.Path;SourceValidated=($null -ne $sourceValidation);SourceArchitecture=if($sourceValidation){$sourceValidation.Architecture}else{$null};SourcePackageName=if($sourceValidation){$sourceValidation.PackageName}else{$null};SourceSha256=if($sourceValidation){$sourceValidation.Sha256}else{$null};CreatedAtUtc=[DateTime]::UtcNow.ToString('o');ExactPayloadRecoverySupported=$false}
  $saved=Save-RideClientComponentSnapshot $record
  try{$nativeResult=Invoke-RideClientComponentNativeTransition -Kind $Kind -Name $Name -DesiredState $DesiredState -SourceMode $SourceMode -SourcePath $plan.SourcePolicy.Path}
  catch{throw "DISM servicing failed after state snapshot $($saved.RunId); inspect the component and use Restore-RideClientComponentTransition if the literal state changed. $($_.Exception.Message)"}
  $after=Get-RideClientComponentFreshState -Kind $Kind -Name $Name -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -LogDirectory $LogDirectory
  $restart=$null;if($nativeResult -and $nativeResult.PSObject.Properties['RestartNeeded']){$restart=[bool]$nativeResult.RestartNeeded}
  [pscustomobject]@{Status=if($after.State -ceq $record.ExpectedState){'Applied'}else{'AppliedPostStateMismatch'};Kind=$Kind;Name=$Name;BeforeState=$fresh.State;AfterState=$after.State;DesiredState=$DesiredState;RunId=$saved.RunId;SnapshotPath=$saved.Path;RestartNeeded=$restart;PostStateVerified=($after.State -ceq $record.ExpectedState);SourceMode=$SourceMode;SourceValidated=($null -ne $sourceValidation);NetworkBoundaryVerified=$false;ExactPayloadRecoverySupported=$false}
}

function Restore-RideClientComponentTransition {
  <#
  .SYNOPSIS
    Restore the captured prior literal state for one client-component run.
  .DESCRIPTION
    Requires matching computer/build/edition, no pending reboot and a live state equal to
    the run's expected post-state. Retains the snapshot and refuses drift. DISM payload
    version/identity recovery remains best effort and is reported as unsupported.
  .PARAMETER RunId
    32-character hexadecimal run ID returned by Invoke-RideClientComponentTransition.
  .PARAMETER ExpectedComputerName
    Local computer expected by the operator.
  .PARAMETER ExpectedBuild
    Exact Windows build expected by the operator.
  .PARAMETER ExpectedEditionId
    Exact Windows EditionID expected by the operator.
  .PARAMETER LogDirectory
    Existing local directory for fresh DISM inventory logs and scratch files.
  .EXAMPLE
    Restore-RideClientComponentTransition -RunId $runId -ExpectedComputerName $env:COMPUTERNAME -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory C:\Evidence -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Restored literal state, restart requirement and fidelity limits.
  .NOTES
    The versioned machine snapshot remains available after restore.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][string]$LogDirectory)
  $record=Read-RideClientComponentSnapshot $RunId
  if([long]$record.Build -lt 22000){throw 'Saved component run targets an undeclared pre-Windows 11 client build.'}
  if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'ClientComponentState' -or $record.ComputerName -ine $ExpectedComputerName -or $record.Build -cne $ExpectedBuild -or $record.EditionId -ine $ExpectedEditionId){throw 'Saved client component state belongs to another target or schema.'}
  if(Test-RideClientComponentPendingReboot){throw 'A Windows servicing restart is pending; restore after it completes.'}
  $fresh=Get-RideClientComponentFreshState -Kind $record.ProviderKind -Name $record.Name -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -LogDirectory $LogDirectory
  if($fresh.Inventory.WindowsContext.UpdateBuildRevision -ne $record.UpdateBuildRevision -or $fresh.State -cne $record.ExpectedState){throw 'Client component target revision or literal state drifted; refusing automatic restore.'}
  if($fresh.State -ceq $record.BeforeState){return [pscustomobject]@{Status='AlreadyRestored';Kind=$record.ProviderKind;Name=$record.Name;State=$fresh.State;RestartNeeded=$false;PostStateVerified=$true;ExactPayloadRecoverySupported=$false;RunId=$RunId}}
  $restoreWouldRemoveUnverifiedPayload=($record.ProviderKind -ceq 'Capability' -and $record.BeforeState -ceq 'NotPresent') -or
    ($record.ProviderKind -ceq 'OptionalFeature' -and $record.BeforeState -ceq 'DisabledWithPayloadRemoved')
  if($restoreWouldRemoveUnverifiedPayload){throw 'Restore would remove or discard a component payload without a validated matching recovery source; the saved state was retained.'}
  $desired=if($record.BeforeState -in @('Installed','Enabled')){'Present'}else{'Absent'}
  if($desired -eq 'Present' -and $record.SourceMode -ceq 'LocalSource'){
    if($record.SourceValidated -cne $true -or $record.SourcePackageName -isnot [string] -or $record.SourceSha256 -isnot [string]){throw 'Restore requires a validated matching LocalSource, but the saved record does not prove source identity or completeness; the saved state was retained.'}
    $sourceValidation=Test-RideClientComponentLocalSource -Kind $record.ProviderKind -Name $record.Name -SourcePath $record.SourcePath -ExpectedBuild $record.Build
    if($sourceValidation.PackageName -cne $record.SourcePackageName -or $sourceValidation.Sha256 -cne $record.SourceSha256 -or $sourceValidation.Architecture -cne $record.SourceArchitecture){throw 'Restore source CAB changed since the saved run; the saved state was retained.'}
  }
  if(-not $PSCmdlet.ShouldProcess("$ExpectedComputerName / $($record.ProviderKind) / $($record.Name)",'Restore captured component state')){return [pscustomobject]@{Status='WhatIf';Kind=$record.ProviderKind;Name=$record.Name;State=$fresh.State;RestartNeeded=$false;PostStateVerified=$false;ExactPayloadRecoverySupported=$false;RunId=$RunId}}
  $result=Invoke-RideClientComponentNativeTransition -Kind $record.ProviderKind -Name $record.Name -DesiredState $desired -SourceMode $record.SourceMode -SourcePath $record.SourcePath -RestoreRemovedPayload:($record.BeforeState -ceq 'DisabledWithPayloadRemoved')
  $after=Get-RideClientComponentFreshState -Kind $record.ProviderKind -Name $record.Name -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -LogDirectory $LogDirectory
  $restart=$null;if($result -and $result.PSObject.Properties['RestartNeeded']){$restart=[bool]$result.RestartNeeded}
  [pscustomobject]@{Status=if($after.State -ceq $record.BeforeState){'Restored'}else{'RestorePostStateMismatch'};Kind=$record.ProviderKind;Name=$record.Name;State=$after.State;RestartNeeded=$restart;PostStateVerified=($after.State -ceq $record.BeforeState);ExactPayloadRecoverySupported=$false;RunId=$RunId}
}

Export-ModuleMember -Function Invoke-RideClientComponentTransition,Restore-RideClientComponentTransition
